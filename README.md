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

## Xray 上游适配

当前配置基线为 **Xray v26.11.9**（提交 `676eaf66f8f05d4d558ee7a74b4736623d3feeb9`）。请先通过组件更新页更新核心；外部 `openwrt-passwall-packages` feed 中的核心配方不在本仓库内，需要同步更新。组件检查直接读取官方 Release 列表，包含预发布、排除草稿，按发布时间选择最新发布；不会自动安装。

“其他设置 → Xray”提供主客户端 JSON 合并入口，Xray 服务端实例也提供独立入口。默认关闭；服务端原有“使用自定义配置”仍是完整替换模式，与合并模式分开使用。常用功能继续使用表单，高级配置可通过 JSON 提供，不使用本地字段白名单过滤未来字段。Xray 可能忽略不认识的字段，因此核心校验通过并不意味着每个字段均生效。

合并规则：

- 对象递归合并，普通数组整体替换，标量替换；`null` 是显式值，不表示删除。
- 顶层入站、出站按非空且唯一的 `tag` 合并；新条目追加，同名条目递归合并。
- 主客户端已有入站参数受保护；服务端保留其监听地址、端口及协议。已有出站协议、代理链和 socket 标记受保护；新增普通客户端出站自动补充绕过标记 255。WireGuard 等专用协议还需按平台验证防回环行为。
- 自动生成的 DNS、FakeDNS、版本约束、反向代理及路由字段受保护；可添加新对象字段；DNS servers 保留托管项并追加去重后的自定义项，路由 balancers 按 tag 保留托管项并追加新项。自定义路由规则排在托管规则之后，已有兜底规则可能使其无法命中；调整托管分流请使用分流页面。
- 主客户端入口只作用于主 Xray 实例，不复制到辅助 DNS、SOCKS 或 ACL 实例，避免重复监听。API、统计、策略、观测、反向代理和额外入出站可通过 JSON 扩展；系统权限、核心构建和上游协议限制仍然适用。

“预览并校验”使用设备安装的 Xray 核心执行 `run -test`。客户端预览基于最近一次生成的主实例骨架，服务端基于已保存的表单；修改其他设置后应先保存并重新生成，再检查 JSON。预览含凭据，请勿公开。配置临时文件使用私有目录和 0600 权限；普通日志和 RPC 不返回核心原始诊断，避免泄露凭据。

启动时先校验配置，再原子替换配置文件；重启前会基于上次骨架预检 JSON，失败则取消重启。**这不是整个服务的事务回滚**：更改其他 UCI 参数、运行时占用端口或进程启动失败，仍可能导致原有“停止后启动”流程中断，尚不具备完整的防火墙、DNS 和进程自动恢复。

XDRIVE 在客户端和服务端传输列表中提供 JSON 设置。它仅适用于 VLESS，必须配置匹配的 encryption/decryption，不能设置 flow；客户端自动启用 Mux，concurrency 和 xudpConcurrency 必须非负。分享链接不能完整表达当前 XDRIVE 配置，导出会提示改用完整 JSON，订阅遇到此类链接会跳过。Google Drive、S3、Yandex 等后端需要各自凭据和网络条件；本地后端已做实际往返测试，外部后端尚未验证。

每周及推送、PR、手动触发的 `Xray upstream compatibility` 工作流检查固定基线和最新 Release，核对官方二进制 SHA-256，保存发布信息、源码提交和配置字段清单。上游 `infra/conf` 字段发生变化会使检查失败，要求维护者复核并更新测试与字段快照；字段快照只能检测配置表面变化，不代替功能审计。

## 检查

```shell
node tests/check.mjs
node --test tests/parse-runtime.test.mjs
```

`check.mjs` 检查 LuCI 脚本语法、运行状态解析和表格拖动排序。`parse-runtime.test.mjs` 检查页面上的 `parseRuntime`。`rpc-plugin.uc` 用同一套 ucode 加载 rpcd 插件并调用设置页的 `capabilities`、`index_status` 和 `get_now_use_node`。插件或它导入的模块只要编译失败，ubus 上就没有 `luci.passwall`，页面会报 `Object not found`。

Xray 合并、核心配置及本地往返测试：

```sh
python3 tests/xray-upstream.py --output /tmp/xray
UCODE=/path/to/ucode UCODE_LIB=/path/to/ucode/build XRAY=/tmp/xray/xray python3 tests/xray-compat.py
```

测试覆盖 JSON 合并保护、发布选择、客户端与服务端常见协议和传输的配置生成，以及 VLESS 各传输（含本地 XDRIVE）、VMess、Trojan、Shadowsocks 经 SOCKS 到 HTTP 的 TCP 往返。测试移除透明代理和 SO_MARK，只在本机临时端口运行。OpenWrt 上的 UDP、IPv6、TLS/REALITY/ECH、DNS、ACL、链式代理和外部服务仍需设备集成验证，不能据此宣称所有上游功能都已验证可用。
