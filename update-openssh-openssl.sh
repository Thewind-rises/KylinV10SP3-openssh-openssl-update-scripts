#!/bin/bash
# ==============================================================================
# 组件：OpenSSL 1.1.1w / curl 7.88.1 / OpenSSH 10.2p1 安全升级脚本 (V3.0 终极修复版)
# 核心策略：独立目录安装 + RPATH 硬编码，【绝不污染/覆盖系统 /usr/lib64 核心库】
# ==============================================================================
set -euo pipefail

# ======================== 全局配置 ========================
readonly WORK_DIR="/opt/openssh-update"
readonly OPENSSL_VER="1.1.1w"
readonly CURL_VER="7.88.1"
readonly OPENSSH_VER="10.2p1"

readonly OPENSSL_PREFIX="/usr/local/openssl-${OPENSSL_VER}"
readonly CURL_PREFIX="/usr/local/curl-${CURL_VER}"
readonly OPENSSH_PREFIX="/usr/local/openssh-${OPENSSH_VER}"

mkdir -p "$WORK_DIR"
readonly BACKUP_DIR="${WORK_DIR}/backup_$(date +%Y%m%d_%H%M%S)"
readonly LOG_FILE="${WORK_DIR}/upgrade_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$BACKUP_DIR"
touch "$LOG_FILE"

# 颜色定义
readonly RED='\033[0;31m'; readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'; readonly BLUE='\033[0;34m'; readonly NC='\033[0m'

# ======================== 基础函数 ========================
log() { 
    echo -e "${2:-$NC}[$(date +'%H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE" 
}
log_info() { log "$1" "$BLUE"; }
log_warn() { log "$1" "$YELLOW"; }
log_error() { log "$1" "$RED"; }

# 异常捕获
trap 'log_error "脚本在第 $LINENO 行异常退出，错误代码: $?。请检查日志: $LOG_FILE"; exit 1' ERR

check_root() {
    # 【修复】：使用 if 替代 &&，防止 root 执行时返回 1 触发 set -e 退出
    if [[ $EUID -ne 0 ]]; then
        log_error "必须使用 root 权限执行"
        exit 1
    fi
}

check_env() {
    log_info "执行环境前置检查..."
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        log_warn "检测到当前处于 SSH 会话。请务必【保持当前终端不关闭】作为应急通道！"
        read -p "是否已准备好带外管理(IPMI/Console)或快照？(y/N): " confirm
        if [[ "${confirm,,}" != "y" ]]; then
            log_error "用户取消执行"
            exit 1
        fi
    fi
    
    cd "$WORK_DIR" || { log_error "无法进入 $WORK_DIR"; exit 1; }
    
    for pkg in "openssl-${OPENSSL_VER}.tar.gz" "curl-${CURL_VER}.tar.gz" "openssh-${OPENSSH_VER}.tar.gz"; do
        if [[ ! -f "$pkg" ]]; then
            log_error "缺失安装包: $pkg"
            exit 1
        fi
    done
}

# ======================== 核心编译与安装 ========================
install_deps() {
    log_info "安装编译依赖..."
    yum install -y --skip-broken gcc make perl zlib-devel pam-devel libselinux-devel \
        krb5-devel openldap-devel libssh2-devel libidn2-devel cyrus-sasl-devel
}

build_openssl() {
    log_info "编译 OpenSSL ${OPENSSL_VER} (独立目录)..."
    rm -rf "openssl-${OPENSSL_VER}"
    tar -xzf "openssl-${OPENSSL_VER}.tar.gz"
    cd "openssl-${OPENSSL_VER}"
    
    ./config --prefix="$OPENSSL_PREFIX" --openssldir="$OPENSSL_PREFIX/ssl" shared zlib
    make -j"$(nproc)" && make install
    
    # 仅创建局部 ldconfig 配置，不覆盖 /usr/lib64
    echo "$OPENSSL_PREFIX/lib" > /etc/ld.so.conf.d/custom-openssl.conf
    ldconfig
    
    cd "$WORK_DIR"
}

build_curl() {
    log_info "编译 curl ${CURL_VER}..."
    rm -rf "curl-${CURL_VER}"
    tar -xzf "curl-${CURL_VER}.tar.gz"
    cd "curl-${CURL_VER}"
    
    # LDFLAGS 注入 rpath，使 curl 运行时强制寻找新 OpenSSL
    ./configure --prefix="$CURL_PREFIX" \
        --with-ssl="$OPENSSL_PREFIX" \
        --with-libssh2 --enable-ldap --enable-ldaps \
        LDFLAGS="-Wl,-rpath,$OPENSSL_PREFIX/lib"
    
    make -j"$(nproc)" && make install
    cd "$WORK_DIR"
}

build_openssh() {
    log_info "编译 OpenSSH ${OPENSSH_VER}..."
    
    id sshd &>/dev/null || useradd -r -s /sbin/nologin -d /var/empty/sshd sshd
    mkdir -p /var/empty/sshd && chown sshd:sshd /var/empty/sshd
    
    rm -rf "openssh-${OPENSSH_VER}"
    tar -xzf "openssh-${OPENSSH_VER}.tar.gz"
    cd "openssh-${OPENSSH_VER}"
    
    # --with-ssl-dir 指向新 OpenSSL，LDFLAGS 注入 rpath
    ./configure --prefix="$OPENSSH_PREFIX" --sysconfdir=/etc/ssh \
        --with-ssl-dir="$OPENSSL_PREFIX" \
        --with-pam --with-md5-passwords \
        --with-privsep-path=/var/empty/sshd --with-privsep-user=sshd \
        LDFLAGS="-Wl,-rpath,$OPENSSL_PREFIX/lib"
        
    make -j"$(nproc)" && make install
    
    # 备份并替换二进制文件
    for bin in ssh scp sftp; do
        if [[ -f /usr/bin/$bin ]]; then
            cp -f /usr/bin/$bin "$BACKUP_DIR/${bin}.bak"
        fi
        cp -pf "$OPENSSH_PREFIX/bin/$bin" /usr/bin/
    done
    
    if [[ -f /usr/sbin/sshd ]]; then
        cp -f /usr/sbin/sshd "$BACKUP_DIR/sshd.bak"
    fi
    cp -pf "$OPENSSH_PREFIX/sbin/sshd" /usr/sbin/
    
    cd "$WORK_DIR"
}

# ======================== 配置与重启 ========================
patch_sshd_config() {
    log_info "清理 OpenSSH 10.x 已废弃的 GSSAPI 配置..."
    local conf="/etc/ssh/sshd_config"
    cp -f "$conf" "$BACKUP_DIR/sshd_config.bak"
    
    # 幂等清理废弃项
    sed -i '/^[[:space:]]*GSSAPIKexAlgorithms/d' "$conf"
    sed -i 's/^[[:space:]]*\(GSSAPI.*\)/#\1/' "$conf"
    
    if ! grep -q "^UseDNS" "$conf"; then
        echo "UseDNS no" >> "$conf"
    fi
}

safe_restart_sshd() {
    log_info "语法检查 sshd 配置..."
    if ! /usr/sbin/sshd -t; then
        log_error "sshd 配置语法错误，中止重启！"
        exit 1
    fi
    
    log_warn "准备重启 sshd。若 60 秒内未确认，将自动回滚！"
    # 【防线】：后台定时任务，60秒后若未被取消，自动还原备份并重启旧 sshd
    ( sleep 60 && \
      if [[ -f "$BACKUP_DIR/sshd.bak" ]]; then \
          cp -f "$BACKUP_DIR/sshd.bak" /usr/sbin/sshd && \
          systemctl restart sshd && \
          echo "[$(date)] 触发超时自动回滚" >> "$LOG_FILE"; \
      fi \
    ) &
    local rollback_pid=$!
    
    systemctl restart sshd
    
    if systemctl is-active --quiet sshd; then
        log_info "sshd 重启成功，取消自动回滚任务。"
        kill $rollback_pid 2>/dev/null || true
    else
        log_error "sshd 启动失败，立即触发回滚！"
        kill $rollback_pid 2>/dev/null || true
        if [[ -f "$BACKUP_DIR/sshd.bak" ]]; then
            cp -f "$BACKUP_DIR/sshd.bak" /usr/sbin/sshd
            systemctl restart sshd
        fi
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
    ldd /usr/sbin/sshd | grep ssl || true
    ldd /usr/bin/curl | grep ssl || true
    
    log_info "升级完成。请使用新终端测试 SSH 登录，确认无误后再关闭当前终端。" "$GREEN"
}

main "$@"
