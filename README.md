## :mega:公告
自 2026 年 6 月 1 日起，Xray Core 内部定时器已自动弃用 `allowInsecure`（跳过证书验证），并要求自签证书必须配置 `pinnedPeerCertSha256`（`pcs` 参数）。

若机场使用自签证书且未提供 `pcs` 参数，节点将无法正常连接。

**解决方法：**

* 向机场获取 `pinnedPeerCertSha256`（`pcs` 参数）；
* 或切换至 Sing-box Core。  

## 运行环境

面向 **OpenWrt 25.12 及更新版本**。透明代理使用 **firewall4 + nftables**，包管理器为 **apk**，官方 `dnsmasq-full` 默认启用 **nftset**。Web 界面是 LuCI 的 JavaScript 视图，后台逻辑使用 ucode。依赖包含 `luci-base`、`firewall4`、`ucode-mod-ubus` 和 `luci-lib-uqr`。

运行状态、nftables 参数和进程记录使用 JSON，旧的 `KEY='value'` 文件仍能读取。进程按参数数组启动，匹配时直接读 `/proc/<pid>/cmdline`。接口状态走 ucode 的 ubus 模块。端口占用直接读 `/proc/net`，节点域名从 UCI 游标导出。主机路由用 `ip route`。删除文件走 ucode 的目录遍历，带 `*` 的路径用 `glob`。字符串、数值和命令输出的解析集中在 `text.uc`。UUID、磁盘空间、可执行文件查找、dnsmasq 配置段和 WireGuard 密钥在 ucode 里读取。证书指纹仍调用 openssl，主机名和端口会先加引号。删除路径只接受绝对路径；带 `*` 的清理也限制在这组字符里。节点分享二维码由 LuCI 的 µQR 生成。

节点列表和分流规则的拖动排序由 `sortable.js` 完成，使用指针事件。状态卡片、警告文字和弹层颜色跟随 LuCI 主题变量。

| 路径 | 作用 |
| --- | --- |
| `luci-app-passwall/htdocs/` | LuCI 页面。公共样式在 `passwall.css`，运行状态解析在 `tools.js` 的 `parseRuntime`。 |
| `luci-app-passwall/root/usr/libexec/passwall/` | 给 procd、热插拔和计划任务调用的 ucode 入口。 |
| `luci-app-passwall/root/usr/share/ucode/passwall/` | 可复用的服务、订阅、nftables 和协议配置库。 |
| `luci-app-passwall/root/usr/share/rpcd/ucode/luci.passwall` | LuCI 通过 ubus 调用的接口。 |

## 📌如何能编译到最新代码？

### 方法1：

执行 `./scripts/feeds update -a` 操作前，在 `feeds.conf.default` **顶部**插入如下代码：

```
src-git passwall_packages https://github.com/Openwrt-Passwall/openwrt-passwall-packages.git;main
src-git passwall_luci https://github.com/ffgan/openwrt-passwall.git;main
```

### 方法2：

在 `./scripts/feeds install -a` 操作完成后，执行以下命令：

```shell
# 移除 openwrt feeds 自带的核心库
rm -rf feeds/packages/net/{xray-core,v2ray-geodata,sing-box,chinadns-ng,dns2socks,hysteria,ipt2socks,microsocks,naiveproxy,shadowsocks-rust,shadowsocksr-libev,simple-obfs,tcping,v2ray-plugin,xray-plugin,geoview,shadow-tls}
git clone https://github.com/Openwrt-Passwall/openwrt-passwall-packages package/passwall-packages

# 移除 openwrt feeds 过时的luci版本
rm -rf feeds/luci/applications/luci-app-passwall
git clone https://github.com/ffgan/openwrt-passwall package/passwall-luci
```

## 检查

```shell
node tests/check.mjs
node --test tests/parse-runtime.test.mjs
```

`check.mjs` 检查 LuCI 脚本语法、运行状态解析和表格拖动排序。`parse-runtime.test.mjs` 检查页面上的 `parseRuntime`。
