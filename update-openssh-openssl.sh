#!/bin/bash
#================================================================
# 脚本名称: openssh_upgrade.sh
# 核心原理: RPATH 物理隔离，绝不污染系统全局 /usr/lib64
# 执行目录: /opt/openssh-update (需提前人工上传离线包)
#================================================================

set -euo pipefail 

trap 'echo "❌ [ERROR] 脚本在第 $LINENO 行执行失败，触发异常捕获！"; exit 1' ERR

# ================= 1. 变量定义 =================
OPENSSL_VER="1.1.1w"
CURL_VER="7.88.1"
OPENSSH_VER="10.2p1"

OPENSSL_DIR="/usr/local/openssl-${OPENSSL_VER}" 
CURL_DIR="/usr/local/curl-${CURL_VER}"          
WORK_DIR="/opt/openssh-update"                  

OPENSSL_PKG="openssl-${OPENSSL_VER}.tar.gz"
CURL_PKG="curl-${CURL_VER}.tar.gz"
OPENSSH_PKG="openssh-${OPENSSH_VER}.tar.gz"

DATE_TAG=$(date +%Y%m%d)

# ================= 2. 入参校验与模式分发 =================
DRY_RUN=false
ROLLBACK=false

for arg in "$@"; do
    case $arg in
        --dry-run) DRY_RUN=true ;;
        --rollback) ROLLBACK=true ;;
        *) echo "未知参数: $arg"; exit 1 ;;
    esac
done

# ================= 3. 权限与只读诊断 =================
if [ "$EUID" -ne 0 ]; then
  echo "❌ 错误: 需要 root 权限！"
  exit 1
fi

if [ "$DRY_RUN" = true ]; then
    echo "🔍 [Dry-Run] 仅执行环境与介质检查..."
    [ -d "$WORK_DIR" ] || { echo "❌ 目录不存在"; exit 1; }
    for pkg in "$OPENSSL_PKG" "$CURL_PKG" "$OPENSSH_PKG"; do
        [ -f "${WORK_DIR}/${pkg}" ] || { echo "❌ 缺失: ${pkg}"; exit 1; }
        echo "   ✅ 找到 ${pkg}"
    done
    systemctl is-active sshd && echo "   ✅ sshd 运行中"
    echo "✅ [Dry-Run] 检查通过。"
    exit 0
fi

# ================= 4. 回滚逻辑 =================
if [ "$ROLLBACK" = true ]; then
    echo "⚠️ [高危操作] 正在执行回滚逻辑..."
    if ls /usr/sbin/sshd.bak.${DATE_TAG} 1> /dev/null 2>&1; then
        cp -f /usr/sbin/sshd.bak.${DATE_TAG} /usr/sbin/sshd
        echo "✅ sshd 已回滚"
    fi
    if [ -f /usr/bin/curl.sys.bak ]; then
        mv -f /usr/bin/curl.sys.bak /usr/bin/curl
        hash -r
        echo "✅ curl 已回滚"
    fi
    systemctl restart sshd
    exit 0
fi

# ================= 5. 环境准备 =================
echo "=========================================="
echo "[1/6] 安装编译依赖..."
echo "=========================================="
mkdir -p "${WORK_DIR}"
cd "${WORK_DIR}"

for pkg in "$OPENSSL_PKG" "$CURL_PKG" "$OPENSSH_PKG"; do
    if [ ! -f "${WORK_DIR}/${pkg}" ]; then
        echo "❌ 致命错误: 缺失离线包 ${pkg}，请上传至 ${WORK_DIR}！"
        exit 1
    fi
done

yum groupinstall -y "Development Tools" > /dev/null 2>&1 || true
yum install -y gcc gcc-c++ make perl zlib-devel pam-devel binutils > /dev/null 2>&1 || true

# ================= 6. 编译 OpenSSL (物理隔离) =================
echo "=========================================="
echo "[2/6] 编译并安装 OpenSSL ${OPENSSL_VER}"
echo "=========================================="

NEED_COMPILE_OPENSSL=true
if [ -x "${OPENSSL_DIR}/bin/openssl" ]; then
    if readelf -d "${OPENSSL_DIR}/bin/openssl" 2>/dev/null | grep -qE "RPATH|RUNPATH"; then
        echo "✅ OpenSSL 已存在且 RPATH 正常，跳过编译。"
        NEED_COMPILE_OPENSSL=false
    else
        echo "⚠️ 发现已存在的 OpenSSL 缺失 RPATH，将清理并重新编译..."
        rm -rf "${OPENSSL_DIR}"
    fi
fi

if [ "$NEED_COMPILE_OPENSSL" = true ]; then
    rm -rf "${WORK_DIR}/openssl-${OPENSSL_VER}"
    tar -xzf "${OPENSSL_PKG}"
    cd "openssl-${OPENSSL_VER}"
    ./config shared --prefix=${OPENSSL_DIR} --openssldir=${OPENSSL_DIR} -Wl,-rpath,${OPENSSL_DIR}/lib
    make -j$(nproc)
    make install
    cd "${WORK_DIR}"
fi

if ! readelf -d ${OPENSSL_DIR}/bin/openssl | grep -qE "RPATH|RUNPATH"; then
    echo "❌ OpenSSL RPATH 注入失败！"
    exit 1
fi

# ================= 7. 编译 cURL (绑定新 OpenSSL) =================
echo "=========================================="
echo "[3/6] 编译并安装 cURL ${CURL_VER}"
echo "=========================================="

NEED_COMPILE_CURL=true
if [ -x "${CURL_DIR}/bin/curl" ]; then
    if readelf -d "${CURL_DIR}/bin/curl" 2>/dev/null | grep -qE "RPATH|RUNPATH"; then
        echo "✅ cURL 已存在且 RPATH 正常，跳过编译。"
        NEED_COMPILE_CURL=false
    else
        echo "⚠️ 发现已存在的 cURL 缺失 RPATH，将清理并重新编译..."
        rm -rf "${CURL_DIR}"
    fi
fi

if [ "$NEED_COMPILE_CURL" = true ]; then
    rm -rf "${WORK_DIR}/curl-${CURL_VER}"
    tar -xzf "${CURL_PKG}"
    cd "curl-${CURL_VER}"
    ./configure \
      --prefix=${CURL_DIR} \
      --with-ssl=${OPENSSL_DIR} \
      --with-zlib \
      LDFLAGS="-Wl,-rpath,${OPENSSL_DIR}/lib"
    make -j$(nproc)
    make install
    cd "${WORK_DIR}"
fi

if [ -f /usr/bin/curl ] && [ ! -f /usr/bin/curl.sys.bak ]; then
    echo "⚠️ 备份系统原生 curl..."
    cp -f /usr/bin/curl /usr/bin/curl.sys.bak
fi
ln -sf ${CURL_DIR}/bin/curl /usr/bin/curl
hash -r 

# ================= 8. 编译 OpenSSH (绑定新 OpenSSL) =================
echo "=========================================="
echo "[4/6] 编译并安装 OpenSSH ${OPENSSH_VER}"
echo "=========================================="
echo "⚠️ 备份系统原生 sshd 和 ssh..."
[ -f /usr/sbin/sshd ] && cp -f /usr/sbin/sshd /usr/sbin/sshd.bak.${DATE_TAG} || true
[ -f /usr/bin/ssh ] && cp -f /usr/bin/ssh /usr/bin/ssh.bak.${DATE_TAG} || true

rm -rf "${WORK_DIR}/openssh-${OPENSSH_VER}"
tar -xzf "${OPENSSH_PKG}"
cd "openssh-${OPENSSH_VER}"
make clean || true

export LDFLAGS="-Wl,-rpath,${OPENSSL_DIR}/lib"
export CPPFLAGS="-I${OPENSSL_DIR}/include"

./configure \
  --prefix=/usr \
  --sysconfdir=/etc/ssh \
  --with-ssl-dir=${OPENSSL_DIR} \
  --with-zlib \
  --with-pam \
  --with-md5-passwords \
  --mandir=/usr/share/man

make -j$(nproc)
make install
cd "${WORK_DIR}"

# ================= 9. 验证与重启 SSH 服务 =================
echo "=========================================="
echo "[5/6] 验证 RPATH 隔离与配置合法性"
echo "=========================================="

# 【修复】同时匹配 libcrypto.so 或 libssl.so，兼容 OpenSSH 10.x 仅链接 libcrypto 的情况
set +o pipefail
SSHD_SSL_PATH=$(ldd /usr/sbin/sshd | grep -E 'libcrypto\.so|libssl\.so' | head -n 1 | awk '{print $3}')
set -o pipefail

if [[ -z "${SSHD_SSL_PATH}" || "${SSHD_SSL_PATH}" != *"openssl-${OPENSSL_VER}"* ]]; then
    echo "❌ [致命错误] sshd 没有正确绑定到新版 OpenSSL！(当前加载: ${SSHD_SSL_PATH:-未找到})"
    echo "🔄 触发自动回滚..."
    if [ -f "/usr/sbin/sshd.bak.${DATE_TAG}" ]; then
        cp -f "/usr/sbin/sshd.bak.${DATE_TAG}" /usr/sbin/sshd
        systemctl restart sshd
        echo "✅ 已回滚至旧版 sshd。"
    else
        echo "⚠️ 未找到旧版 sshd 备份，请手动排查！"
    fi
    exit 1
fi
echo "✅ sshd 已成功绑定至: ${SSHD_SSL_PATH}"

# 验证 sshd_config 语法
/usr/sbin/sshd -t || { 
    echo "❌ [致命错误] sshd_config 语法检查失败！触发自动回滚..."; 
    cp -f /usr/sbin/sshd.bak.${DATE_TAG} /usr/sbin/sshd; 
    systemctl restart sshd
    exit 1; 
}
echo "✅ sshd_config 语法检查通过。"

echo "=========================================="
echo "[6/6] 重启 SSH 服务"
echo "=========================================="
systemctl enable sshd 2>/dev/null || true
echo "正在重启 sshd 服务..."
systemctl restart sshd

# ================= 最终验收 =================
echo "=========================================="
echo "🎉 升级全部完成！请核对以下版本信息："
echo "=========================================="
echo "1. OpenSSL: $(${OPENSSL_DIR}/bin/openssl version)"
echo "2. cURL: $(curl --version | head -n 1)"
echo "3. OpenSSH: $(ssh -V 2>&1)"
echo "4. sshd SSL 库: $(ldd /usr/sbin/sshd | grep -E 'ssl|crypto')"
echo "5. yum 健康度: $(yum --version | head -n 1)"
echo "=========================================="
echo "⚠️ 警告：在确认能够通过【新终端】成功 SSH 登录之前，绝对禁止关闭当前终端窗口！"
echo "=========================================="
