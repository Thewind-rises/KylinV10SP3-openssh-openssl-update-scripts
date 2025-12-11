#!/bin/bash

# 设置颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查函数
check_result() {
    if [ $? -eq 0 ]; then
        log_success "$1"
        return 0
    else
        log_error "$2"
        exit 1
    fi
}

# 检查是否以root用户运行
check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_error "此脚本必须以root用户运行！"
        exit 1
    fi
}

# 检查执行目录
check_working_dir() {
    local expected_dir="/opt/openssh-update"
    if [ "$(pwd)" != "$expected_dir" ]; then
        log_warn "当前目录不是 $expected_dir，正在切换目录..."
        cd "$expected_dir" 2>/dev/null || {
            log_error "无法切换到 $expected_dir 目录，请确保目录存在"
            exit 1
        }
        log_info "已切换到 $expected_dir 目录"
    fi
}

# 检查必需文件
check_required_files() {
    local required_files=(
        "openssh-10.2p1.tar.gz"
        "openssl-3.0.18.tar.gz"
    )
    
    log_info "检查必需文件..."
    
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            log_error "找不到必需文件: $file"
            log_info "请确保以下文件已上传到 /opt/openssh-update 目录:"
            log_info "1. openssh-10.2p1.tar.gz"
            log_info "2. openssl-3.0.18.tar.gz"
            exit 1
        fi
        log_info "找到文件: $file"
    done
    log_success "所有必需文件都存在"
}

# 备份重要文件
backup_files() {
    local backup_dir="/opt/openssh-update/backup_$(date +%Y%m%d_%H%M%S)"
    log_info "创建备份目录: $backup_dir"
    mkdir -p "$backup_dir"
    
    # 备份现有的ssh和openssl相关文件
    cp -f /usr/bin/openssl "$backup_dir/" 2>/dev/null
    cp -f /usr/bin/ssh "$backup_dir/" 2>/dev/null
    cp -f /usr/sbin/sshd "$backup_dir/" 2>/dev/null
    cp -f /usr/lib64/libssl.so* "$backup_dir/" 2>/dev/null
    cp -f /usr/lib64/libcrypto.so* "$backup_dir/" 2>/dev/null
    cp -f /etc/ssh/sshd_config "$backup_dir/" 2>/dev/null
    
    # 备份要修改的配置文件
    [ -f /etc/crypto-policies/back-ends/openssh.config ] && cp -f /etc/crypto-policies/back-ends/openssh.config "$backup_dir/"
    [ -f /etc/ssh/ssh_config.d/05-redhat.conf ] && cp -f /etc/ssh/ssh_config.d/05-redhat.conf "$backup_dir/"
    
    log_success "重要文件已备份到 $backup_dir"
}

# 安装依赖包
install_dependencies() {
    log_info "开始安装依赖包..."
    
    yum install -y wget vim gdb imake libXt-devel gtk2-devel rpm-build zlib-devel openssl-devel gcc perl perl-IPC-Cmd perl-devel pam-devel unzip krb5-devel libX11-devel initscripts
    
    check_result "依赖包安装成功" "依赖包安装失败"
    
    yum install -y gcc make pam-devel zlib-devel wget tar
    
    check_result "基础开发工具安装成功" "基础开发工具安装失败"
    
    yum install -y libselinux-devel krb5-devel
    
    check_result "其他依赖包安装成功" "其他依赖包安装失败"
}

# 安装 OpenSSL
install_openssl() {
    log_info "开始安装 OpenSSL 3.0.18..."
    
    # 检查是否已解压
    if [ ! -d "openssl-3.0.18" ]; then
        log_info "解压 openssl-3.0.18.tar.gz..."
        tar -xzf openssl-3.0.18.tar.gz
        check_result "OpenSSL 解压成功" "OpenSSL 解压失败"
    fi
    
    cd openssl-3.0.18 || {
        log_error "无法进入 openssl-3.0.18 目录"
        exit 1
    }
    
    log_info "配置 OpenSSL..."
    ./config --prefix=/usr/local/openssl-3.0.18 shared zlib --openssldir=/etc/ssl
    check_result "OpenSSL 配置成功" "OpenSSL 配置失败"
    
    log_info "编译 OpenSSL (使用多核加速)..."
    make -j$(nproc)
    check_result "OpenSSL 编译成功" "OpenSSL 编译失败"
    
    log_info "安装 OpenSSL..."
    make install
    check_result "OpenSSL 安装成功" "OpenSSL 安装失败"
    
    # 备份并创建软链接
    log_info "配置 OpenSSL 库文件..."
    
    [ -f /usr/lib64/libssl.so ] && mv /usr/lib64/libssl.so /usr/lib64/libssl.so.backup
    [ -f /usr/lib64/libcrypto.so ] && mv /usr/lib64/libcrypto.so /usr/lib64/libcrypto.so.backup
    
    ln -sf /usr/local/openssl-3.0.18/lib/libssl.so.3 /usr/lib64/ 2>/dev/null
    ln -sf /usr/local/openssl-3.0.18/lib/libcrypto.so.3 /usr/lib64/ 2>/dev/null
    
    # 配置动态链接库
    echo /usr/local/openssl-3.0.18/lib > /etc/ld.so.conf.d/openssl-3.0.18.conf
    ldconfig -v | grep -E "ssl|crypto" | head -5
    
    # 更新 openssl 命令
    [ -f /usr/bin/openssl ] && mv /usr/bin/openssl /usr/bin/openssl.old
    ln -sf /usr/local/openssl-3.0.18/bin/openssl /usr/bin/openssl
    
    log_info "验证 OpenSSL 安装..."
    openssl version
    check_result "OpenSSL 版本检查完成" "OpenSSL 版本检查失败"
    
    log_info "检查 OpenSSL 库依赖..."
    ldd /usr/bin/openssl | grep -E "ssl|crypto"
    
    cd ..
    log_success "OpenSSL 3.0.18 安装完成"
}

# 修改 SSH 配置
modify_ssh_config() {
    log_info "修改 SSH 配置以禁用 GSSAPI..."
    
    # 备份原始配置
    cp -f /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # 注释 GSSAPI 相关配置
    sed -i '/^GSSAPIAuthentication/s/^/# /' /etc/ssh/sshd_config
    sed -i '/^GSSAPICleanupCredentials/s/^/# /' /etc/ssh/sshd_config
    sed -i '/^GSSAPIStrictAcceptorCheck/s/^/# /' /etc/ssh/sshd_config
    sed -i '/^GSSAPIKeyExchange/s/^/# /' /etc/ssh/sshd_config
    sed -i '/^GSSAPIStoreCredentialsOnRekey/s/^/# /' /etc/ssh/sshd_config
    sed -i '/^[[:space:]]*[^#[:space:]]*RhostsRSAAuthentication[[:space:]]/s/^[[:space:]]*/&#/' /etc/ssh/sshd_config
    sed -i '/^[[:space:]]*[^#[:space:]]*RSAAuthentication[[:space:]]/s/^[[:space:]]*/&#/' /etc/ssh/sshd_config
    
    # 添加必要的配置（确保SSH可以正常工作）
    if ! grep -q "^UseDNS" /etc/ssh/sshd_config; then
        echo "UseDNS no" >> /etc/ssh/sshd_config
    fi
    
    if ! grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
        echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
    fi
    
    log_success "SSH 配置修改完成"
}

# 修改其他GSSAPI相关配置文件
modify_gssapi_configs() {
    log_info "修改其他GSSAPI相关配置文件..."
    
    # 1. 修改 /etc/crypto-policies/back-ends/openssh.config
    if [ -f /etc/crypto-policies/back-ends/openssh.config ]; then
        log_info "修改 /etc/crypto-policies/back-ends/openssh.config 文件..."
        if grep -q "GSSAPIKexAlgorithms" /etc/crypto-policies/back-ends/openssh.config; then
            sed -i '/^.*GSSAPIKexAlgorithms/s/^/# /' /etc/crypto-policies/back-ends/openssh.config
            log_success "已注释 /etc/crypto-policies/back-ends/openssh.config 中的 GSSAPIKexAlgorithms 配置"
        else
            log_warn "/etc/crypto-policies/back-ends/openssh.config 中没有找到 GSSAPIKexAlgorithms 配置"
        fi
    else
        log_warn "/etc/crypto-policies/back-ends/openssh.config 文件不存在，跳过修改"
    fi
    
    # 2. 修改 /etc/ssh/ssh_config.d/05-redhat.conf
    if [ -f /etc/ssh/ssh_config.d/05-redhat.conf ]; then
        log_info "修改 /etc/ssh/ssh_config.d/05-redhat.conf 文件..."
        if grep -q "GSSAPIAuthentication" /etc/ssh/ssh_config.d/05-redhat.conf; then
            sed -i '/^.*GSSAPIAuthentication/s/^/# /' /etc/ssh/ssh_config.d/05-redhat.conf
            log_success "已注释 /etc/ssh/ssh_config.d/05-redhat.conf 中的 GSSAPIAuthentication 配置"
        else
            log_warn "/etc/ssh/ssh_config.d/05-redhat.conf 中没有找到 GSSAPIAuthentication 配置"
        fi
    else
        log_warn "/etc/ssh/ssh_config.d/05-redhat.conf 文件不存在，跳过修改"
    fi
    
    # 3. 修改 /etc/ssh/ssh_config（如果存在相关配置）
    if [ -f /etc/ssh/ssh_config ]; then
        log_info "检查 /etc/ssh/ssh_config 文件中的 GSSAPI 配置..."
        if grep -q "^GSSAPIAuthentication" /etc/ssh/ssh_config; then
            sed -i '/^GSSAPIAuthentication/s/^/# /' /etc/ssh/ssh_config
            log_success "已注释 /etc/ssh/ssh_config 中的 GSSAPIAuthentication 配置"
        fi
        
        if grep -q "^GSSAPIDelegateCredentials" /etc/ssh/ssh_config; then
            sed -i '/^GSSAPIDelegateCredentials/s/^/# /' /etc/ssh/ssh_config
            log_success "已注释 /etc/ssh/ssh_config 中的 GSSAPIDelegateCredentials 配置"
        fi
    fi
    
    log_success "GSSAPI 相关配置修改完成"
}

# 安装 OpenSSH
install_openssh() {
    log_info "开始安装 OpenSSH 10.2p1..."
    
    # 检查是否已解压
    if [ ! -d "openssh-10.2p1" ]; then
        log_info "解压 openssh-10.2p1.tar.gz..."
        tar -xzf openssh-10.2p1.tar.gz
        check_result "OpenSSH 解压成功" "OpenSSH 解压失败"
    fi
    
    cd openssh-10.2p1 || {
        log_error "无法进入 openssh-10.2p1 目录"
        exit 1
    }
    
    log_info "配置 OpenSSH..."
    ./configure \
        --prefix=/usr/local/openssh-10.2p1 \
        --sysconfdir=/etc/ssh \
        --with-openssl-includes=/usr/local/openssl-3.0.18/include \
        --with-ssl-dir=/usr/local/openssl-3.0.18 \
        --with-zlib \
        --with-pam \
        --with-md5-passwords \
        --with-privsep-path=/var/empty/sshd \
        --with-privsep-user=sshd
    check_result "OpenSSH 配置成功" "OpenSSH 配置失败"
    
    log_info "编译 OpenSSH (使用多核加速)..."
    make -j$(nproc)
    check_result "OpenSSH 编译成功" "OpenSSH 编译失败"
    
    log_info "安装 OpenSSH..."
    make install
    check_result "OpenSSH 安装成功" "OpenSSH 安装失败"
    
    # 复制文件到系统目录
    log_info "部署 OpenSSH 文件..."
    
    # 备份原有文件
    [ -f /usr/bin/ssh ] && cp -f /usr/bin/ssh /usr/bin/ssh.backup
    [ -f /usr/bin/scp ] && cp -f /usr/bin/scp /usr/bin/scp.backup
    [ -f /usr/sbin/sshd ] && cp -f /usr/sbin/sshd /usr/sbin/sshd.backup
    
    # 复制新文件
    cp -pf /usr/local/openssh-10.2p1/bin/ssh /usr/local/openssh-10.2p1/bin/scp /usr/bin/
    cp -pf /usr/local/openssh-10.2p1/sbin/sshd /usr/sbin/
    ln -sf /usr/local/openssh-10.2p1/bin/ssh-keygen /usr/bin/ssh-keygen 2>/dev/null
    
    # 复制man文档
    mkdir -p /usr/share/man/man8 /usr/share/man/man1
    cp -pf /usr/local/openssh-10.2p1/share/man/man8/sshd.8 /usr/share/man/man8/ 2>/dev/null
    cp -pf /usr/local/openssh-10.2p1/share/man/man1/ssh.1 /usr/share/man/man1/ 2>/dev/null
    
    # 创建sshd用户和目录（如果不存在）
    if ! id sshd &>/dev/null; then
        useradd -r -s /sbin/nologin -d /var/empty/sshd sshd 2>/dev/null
        mkdir -p /var/empty/sshd
        chown sshd:sshd /var/empty/sshd
    fi
    
    # 复制配置文件样本
    if [ ! -f /etc/ssh/sshd_config.rpmnew ]; then
        cp -f sshd_config /etc/ssh/sshd_config.rpmnew
    fi
    
    cd ..
    log_success "OpenSSH 10.2p1 安装完成"
}

# 重启SSH服务
restart_ssh_service() {
    log_info "重新加载系统守护进程..."
    systemctl daemon-reload
    check_result "系统守护进程重新加载成功" "系统守护进程重新加载失败"
    
    log_info "重启 SSH 服务..."
    systemctl restart sshd
    if [ $? -eq 0 ]; then
        log_success "SSH 服务重启成功"
        
        # 检查服务状态
        log_info "检查 SSH 服务状态..."
        systemctl status sshd --no-pager -l
    else
        log_warn "SSH 服务重启失败，尝试手动启动..."
        /usr/sbin/sshd -t
        if [ $? -eq 0 ]; then
            systemctl start sshd
            check_result "SSH 服务启动成功" "SSH 服务启动失败"
        else
            log_error "SSH 配置测试失败，请检查配置"
            exit 1
        fi
    fi
}

# 验证安装
verify_installation() {
    log_info "验证安装结果..."
    
    echo -e "\n${BLUE}=== OpenSSL 版本 ===${NC}"
    openssl version
    
    echo -e "\n${BLUE}=== OpenSSH 版本 ===${NC}"
    ssh -V 2>&1
    
    echo -e "\n${BLUE}=== SSH 服务状态 ===${NC}"
    systemctl is-active sshd
    
    echo -e "\n${BLUE}=== 检查监听端口 ===${NC}"
    netstat -tlnp | grep sshd
    
    echo -e "\n${BLUE}=== GSSAPI 配置状态 ===${NC}"
    echo "检查 /etc/ssh/sshd_config 中的 GSSAPI 配置:"
    grep -E "^#.*GSSAPI|^GSSAPI" /etc/ssh/sshd_config || echo "未找到GSSAPI配置"
    
    echo -e "\n检查 /etc/crypto-policies/back-ends/openssh.config 中的 GSSAPI 配置:"
    if [ -f /etc/crypto-policies/back-ends/openssh.config ]; then
        grep -E "^#.*GSSAPI|GSSAPI" /etc/crypto-policies/back-ends/openssh.config || echo "未找到GSSAPI配置"
    else
        echo "文件不存在"
    fi
    
    echo -e "\n检查 /etc/ssh/ssh_config.d/05-redhat.conf 中的 GSSAPI 配置:"
    if [ -f /etc/ssh/ssh_config.d/05-redhat.conf ]; then
        grep -E "^#.*GSSAPI|^GSSAPI" /etc/ssh/ssh_config.d/05-redhat.conf || echo "未找到GSSAPI配置"
    else
        echo "文件不存在"
    fi
    
    echo -e "\n${BLUE}=== 重要文件备份位置 ===${NC}"
    find /opt/openssh-update -name "backup_*" -type d | sort | tail -1
}

# 主函数
main() {
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}   OpenSSL 和 OpenSSH 升级脚本         ${NC}"
    echo -e "${GREEN}   (包含GSSAPI配置修改)                ${NC}"
    echo -e "${GREEN}========================================${NC}"
    
    # 执行步骤
    check_root
    check_working_dir
    check_required_files
    backup_files
    install_dependencies
    install_openssl
    modify_ssh_config
    modify_gssapi_configs  # 新增：修改其他GSSAPI配置文件
    install_openssh
    restart_ssh_service
    verify_installation
    
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}  升级完成！                           ${NC}"
    echo -e "${GREEN}  请使用 'ssh -V' 验证版本             ${NC}"
    echo -e "${GREEN}  请测试SSH连接确保服务正常           ${NC}"
    echo -e "${GREEN}========================================${NC}"
    
    # 显示修改的配置文件内容
    echo -e "\n${YELLOW}已修改的GSSAPI配置摘要:${NC}"
    echo -e "${YELLOW}1. /etc/ssh/sshd_config:${NC}"
    grep -E "^#.*GSSAPI" /etc/ssh/sshd_config | head -5
    
    if [ -f /etc/crypto-policies/back-ends/openssh.config ]; then
        echo -e "\n${YELLOW}2. /etc/crypto-policies/back-ends/openssh.config:${NC}"
        grep -E "^#.*GSSAPI" /etc/crypto-policies/back-ends/openssh.config
    fi
    
    if [ -f /etc/ssh/ssh_config.d/05-redhat.conf ]; then
        echo -e "\n${YELLOW}3. /etc/ssh/ssh_config.d/05-redhat.conf:${NC}"
        grep -E "^#.*GSSAPI" /etc/ssh/ssh_config.d/05-redhat.conf
    fi
}

# 执行主函数
main
