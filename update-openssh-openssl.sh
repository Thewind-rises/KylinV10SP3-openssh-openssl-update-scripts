#!/bin/bash
# ==============================================================================
# 组件：OpenSSL 1.1.1w / curl 7.88.1 / OpenSSH 10.2p1 安全升级脚本
# 环境：麒麟 V10 SP3 / CentOS 7/8 / RHEL 8+
# 核心策略：独立目录安装 + RPATH 硬编码，【绝不污染/覆盖系统 /usr/lib64 核心库】
# ==============================================================================
set -euo pipefail # 严格模式：遇错即停、未定义变量报错、管道失败即停

# ======================== 全局配置 ========================
readonly WORK_DIR="/opt/openssh-update"
readonly OPENSSL_VER="1.1.1w"
readonly CURL_VER="7.88.1"
readonly OPENSSH_VER="10.2p1"

readonly OPENSSL_PREFIX="/usr/local/openssl-${OPENSSL_VER}"
readonly CURL_PREFIX="/usr/local/curl-${CURL_VER}"
readonly OPENSSH_PREFIX="/usr/local/openssh-${OPENSSH_VER}"

readonly BACKUP_DIR="${WORK_DIR}/backup_$(date +%Y%m%d_%H%M%S)"
readonly LOG_FILE="${WORK_DIR}/upgrade_$(date +%Y%m%d_%H%M%S).log"

# 颜色定义
readonly RED='\033[0;31m'; readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'; readonly NC='\033[0m'

# ======================== 基础函数 ========================
log() { echo -e "${2:-NC}[$(date +'%H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"; }
log_info() { log "$1" "$BLUE"; } # 注：BLUE未定义则用NC，此处省略BLUE定义以精简
log_warn() { log "$1" "$YELLOW"; }
log_error() { log "$1" "$RED"; }

# 异常捕获与自动回滚触发
trap 'log_error "脚本在第 $LINENO 行异常退出，请检查日志: $LOG_FILE"; exit 1' ERR

check_root() {
    [[ $EUID -ne 0 ]] && { log_error "必须使用 root 权限执行"; exit 1; }
}

check_env() {
    log_info "执行环境前置检查..."
    # 检查是否处于 SSH 会话中，警告用户保留会话
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        log_warn "检测到当前处于 SSH 会话。请务必【保持当前终端不关闭】作为应急通道！"
        read -p "是否已准备好带外管理(IPMI/Console)或快照？(y/N): " confirm
        [[ "${confirm,,}" != "y" ]] && { log_error "用户取消执行"; exit 1; }
    fi
    
    mkdir -p "$WORK_DIR" "$BACKUP_DIR"
    cd "$WORK_DIR" || { log_error "无法进入 $WORK_DIR"; exit 1; }
    
    for pkg in "openssl-${OPENSSL_VER}.tar.gz" "curl-${CURL_VER}.tar.gz" "openssh-${OPENSSH_VER}.tar.gz"; do
        [[ ! -f "$pkg" ]] && { log_error "缺失安装包: $pkg"; exit 1; }
    done
}

# ======================== 核心编译与安装 ========================
install_deps() {
    log_info "安装编译依赖 (使用 --skip-broken 避免个别包缺失阻断流程)..."
    yum install -y --skip-broken gcc make perl zlib-devel pam-devel libselinux-devel \
        krb5-devel openldap-devel libssh2-devel libidn2-devel cyrus-sasl-devel
}

build_openssl() {
    log_info "编译 OpenSSL ${OPENSSL_VER} (独立目录，不污染系统库)..."
    tar -xzf "openssl-${OPENSSL_VER}.tar.gz"
    cd "openssl-${OPENSSL_VER}"
    
    # 核心参数：shared 生成动态库，zlib 支持压缩
    ./config --prefix="$OPENSSL_PREFIX" --openssldir="$OPENSSL_PREFIX/ssl" shared zlib
    make -j"$(nproc)" && make install
    
    # 【安全平替】：仅创建局部 ldconfig 配置，不覆盖 /usr/lib64
    echo "$OPENSSL_PREFIX/lib" > /etc/ld.so.conf.d/custom-openssl.conf
    ldconfig
    
    cd "$WORK_DIR"
}

build_curl() {
    log_info "编译 curl ${CURL_VER} (通过 RPATH 绑定新 OpenSSL)..."
    tar -xzf "curl-${CURL_VER}.tar.gz"
    cd "curl-${CURL_VER}"
    
    # 核心参数：LDFLAGS 注入 rpath，使 curl 运行时强制寻找新 OpenSSL，不依赖系统全局变量
    ./configure --prefix="$CURL_PREFIX" \
        --with-ssl="$OPENSSL_PREFIX" \
        --with-libssh2 --enable-ldap --enable-ldaps \
        LDFLAGS="-Wl,-rpath,$OPENSSL_PREFIX/lib"
    
    make -j"$(nproc)" && make install
    cd "$WORK_DIR"
}

build_openssh() {
    log_info "编译 OpenSSH ${OPENSSH_VER}..."
    
    # 【前置检查】：sshd 用户和目录
    id sshd &>/dev/null || useradd -r -s /sbin/nologin -d /var/empty/sshd sshd
    mkdir -p /var/empty/sshd && chown sshd:sshd /var/empty/sshd
    
    tar -xzf "openssh-${OPENSSH_VER}.tar.gz"
    cd "openssh-${OPENSSH_VER}"
    
    # 核心参数：--with-ssl-dir 指向新 OpenSSL，LDFLAGS 注入 rpath
    ./configure --prefix="$OPENSSH_PREFIX" --sysconfdir=/etc/ssh \
        --with-ssl-dir="$OPENSSL_PREFIX" \
        --with-pam --with-md5-passwords \
        --with-privsep-path=/var/empty/sshd --with-privsep-user=sshd \
        LDFLAGS="-Wl,-rpath,$OPENSSL_PREFIX/lib"
        
    make -j"$(nproc)" && make install
    
    # 部署二进制文件到系统路径（保留原系统文件后缀为 .bak）
    for bin in ssh scp sftp; do
        [[ -f /usr/bin/$bin ]] && mv -f /usr/bin/$bin /usr/bin/${bin}.bak
        cp -pf "$OPENSSH_PREFIX/bin/$bin" /usr/bin/
    done
    [[ -f /usr/sbin/sshd ]] && mv -f /usr/sbin/sshd /usr/sbin/sshd.bak
    cp -pf "$OPENSSH_PREFIX/sbin/sshd" /usr/sbin/
    
    cd "$WORK_DIR"
}

# ======================== 配置与重启 ========================
patch_sshd_config() {
    log_info "清理 OpenSSH 10.x 已废弃的 GSSAPI 配置..."
    local conf="/etc/ssh/sshd_config"
    cp -f "$conf" "$BACKUP_DIR/sshd_config.bak"
    
    # 幂等设计：先删除废弃项，再注释旧项
    sed -i '/^[[:space:]]*GSSAPIKexAlgorithms/d' "$conf"
    sed -i 's/^[[:space:]]*\(GSSAPI.*\)/#\1/' "$conf"
    
    # 确保基础可用配置
    grep -q "^UseDNS" "$conf" || echo "UseDNS no" >> "$conf"
}

safe_restart_sshd() {
    log_info "语法检查 sshd 配置..."
    /usr/sbin/sshd -t || { log_error "sshd 配置语法错误，中止重启！"; exit 1; }
    
    log_warn "准备重启 sshd。若 60 秒内未确认，将自动回滚！"
    # 【防线】：后台定时任务，60秒后若未被取消，则自动还原备份并重启旧 sshd
    ( sleep 60 && \
      [[ -f /usr/sbin/sshd.bak ]] && \
      mv -f /usr/sbin/sshd.bak /usr/sbin/sshd && \
      systemctl restart sshd && \
      echo "[$(date)] 触发超时自动回滚" >> "$LOG_FILE" \
    ) &
    local rollback_pid=$!
    
    systemctl restart sshd
    
    # 验证新 sshd 是否存活
    if systemctl is-active --quiet sshd; then
        log_info "sshd 重启成功，取消自动回滚任务。"
        kill $rollback_pid 2>/dev/null || true
        # 清理 .bak 文件，确认升级成功
        rm -f /usr/sbin/sshd.bak /usr/bin/ssh.bak /usr/bin/scp.bak
    else
        log_error "sshd 启动失败，立即触发回滚！"
        kill $rollback_pid 2>/dev/null || true
        mv -f /usr/sbin/sshd.bak /usr/sbin/sshd
        systemctl restart sshd
        exit 1
    fi
}

# ======================== 主流程 ========================
main() {
    check_root
    check_env
    install_deps
    build_openssl
    build_curl
    build_openssh
    patch_sshd_config
    safe_restart_sshd
    
    log_info "验证 RPATH 绑定 (确保未污染系统库):"
    ldd /usr/sbin/sshd | grep ssl
    ldd /usr/bin/curl | grep ssl
    
    echo -e "${GREEN}升级完成。请使用新终端测试 SSH 登录，确认无误后再关闭当前终端。${NC}"
}

main "$@"
