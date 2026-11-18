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

启动时先校验配置，再原子替换配置文件；重启前会基于上次骨架预检 JSON，失败则取消重启。成功启动后，以 0600 权限保存 `/etc/passwall/last-good.conf`；后续启动失败会停止残留组件、恢复这份 UCI 配置并重新生成服务。被拒绝的候选配置保存在 `/tmp/passwall-failed.conf`，同样含凭据且权限为 0600。恢复后仍返回失败，让调用方知道本次配置未应用。这是停止后重建的补偿回滚，不是跨进程原子事务，也不能迁移已建立的连接。首次安装没有成功快照时无法恢复；外部规则文件、核心二进制和其他软件的配置不在快照内。

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

## 界面更新与 SSH 安装

界面资源随 `luci-app-passwall` 包一起安装，无需 CDN、外部字体或额外 Web 服务。首页提供状态总览、节点配置定位和代理日志入口；监听端口等高级设置默认折叠。手机与电脑共用同一套页面，宽列表在配置区域内部滚动。

在与设备版本、架构匹配的 OpenWrt SDK 或源码树中，按上文配置 feeds 后构建：

```sh
make package/luci-app-passwall/compile V=s
```

将生成的 `luci-app-passwall` APK 上传到设备 `/tmp/`，通过 SSH 安装（将文件名替换成实际上传的包名）：

```sh
apk add --allow-untrusted /tmp/luci-app-passwall-实际版本.apk
```

仅对自己构建且来源可信的本地包使用 `--allow-untrusted`。本仓库面向 OpenWrt 25.12 及更新版本；不要把 APK 安装到使用 opkg 的旧系统。更新前建议在 LuCI「系统 → 备份/升级」导出备份。安装后重新打开 PassWall 页面，必要时强制刷新浏览器缓存。界面更新不要求重启路由器。

本地可运行 `node tests/check.mjs` 和 `node tests/parse-runtime.test.mjs`。真实设备验收应覆盖 360px、768px、桌面宽度及所用 LuCI 明暗主题，检查无节点、停止运行、连通性检测失败、保存应用和折叠区校验。源码环境的检查不能替代这些设备验收。


## OpenWrt 可靠性与链路调优

- nftables 每个批次先 `nft -c` 校验，再原子提交；错误会中止，不再逐条安装部分规则。地址集合入口过滤不合法的 IPv4/IPv6 CIDR，避免订阅中的无效数据破坏整个批次。不同批次、策略路由和进程启动之间仍依赖服务恢复流程。
- 透明代理独占 `0x40000000` 标记位，策略路由使用同位掩码，分类时仅同步此位并保留其他软件的 mark 位；升级会清理旧版完整标记规则。最低 8 位的 255 仍保留为现有出站绕过约定。与其他软件同时使用前仍需检查它们是否占用此位。策略路由先于透明代理规则准备，失败会向上传递；重复启动使用幂等路由操作。停用时恢复本服务记录的 `rp_filter`，不会覆盖运行中已被其他管理者改为非零的值。首次改造无法推断旧版本已经修改前的值。
- `passwall_monitor` 由 procd 托管。工作进程每 5 秒扫描所记录的代理进程，失败重试按 5、10、20 秒递增，上限 300 秒；连续存活 60 秒后清除失败计数。不会因为十次失败停止恢复一整天。主 Xray 已作为 `passwall_core/global` 直接注册到 procd，不再创建轮询恢复记录；辅助核心和其他后端仍使用记录管理器。主实例启动确认会轮询实际运行状态、PID 和重启策略，不能以 `service set` 的空结果判失败。ubus 输入的 respawn 使用字符串数组，list 输出则为对象。
- WAN ifup 事件在同一接口锁内等待 3 秒合并关联事件；ifupdate 继续仅更新 WAN 集合。进程清理排除当前进程及其祖先进程，避免 SSH/LuCI 调用参数包含 Passwall 路径时误杀管理通道。
- Xray 节点提供内核实际可用的拥塞算法、keepalive、TCP user timeout、Happy Eyeballs 延迟与并发参数。Happy Eyeballs 使用双栈 `UseIP`，代理链的 `dialerProxy` 出站不生成无效的竞速设置。未填写的 socket 参数保留核心默认值；不可用的拥塞算法拒绝生成。
- 节点 bootstrap DNS 支持 IPv6 地址及端口，不再错误拆分 IPv6 冒号；节点解析关闭过期答案复用。Passwall 独立 dnsmasq 实例启动前执行配置检查。DNS 数据面仍沿用现有 dnsmasq/chinadns 分工；nft 动态集合超时仍为 2 天，尚未实现逐答案 TTL 同步，不能将其称为完整 DNS 一致性重构。
- SOCKS 自动切换支持最多四个探测目标；任一成功即保持健康。默认连续三次失败才切换，恢复主节点需连续三次成功，并有 60 秒冷却。WAN 失联会清除判定计数。Xray 原生 Observatory/BurstObservatory 仍按现有均衡配置使用，尚未增加应用层滞回控制。

设备链路调优在安装对应内核版本的 `kmod-tcp-bbr`、`kmod-sched-cake`、`sqm-scripts` 后运行：

```sh
# 在路由器执行，参数为 Mbps；以 95% 带宽配置双向 CAKE。
sh /tmp/tune-openwrt.sh 200 40
```

脚本位于 `scripts/tune-openwrt.sh`，默认 WAN 为 netifd 的 `wan` 接口；200/40 对应 190000/38000 Kbps。启用按主机公平排队，并关闭与 SQM 冲突的软件/硬件 forwarding offload。默认 Ethernet/PPPoE overhead 为保守的 44 字节，特殊接入应实测调整。对当前普通 TCP 代理节点开启已可用的 BBR、Happy Eyeballs 和保守的存活检测参数。复合分流节点应在各成员节点配置参数。调优失败会恢复脚本修改前的配置，备份位于私有 `/tmp/passwall-tuning.*` 目录。

SQM 会牺牲部分峰值吞吐，实际能力受路由器 CPU 影响；BBR 只控制本机发出的 TCP 数据，不能替远端服务器选择下载拥塞算法。MPTCP、TFO、Vision、REALITY、XHTTP 和 UDP 传输依赖对端及网络条件，不随本脚本强制开启。AX3000T 上已验证失败配置回滚后代理返回 HTTP 204；监控进程被终止后由 procd 在 5 秒恢复，Xray 被终止后在 6 秒恢复。未做生产网络的断 WAN、重启设备、IPv6 UDP 全矩阵或满载 P95/P99 性能验收。

新增检查：

```sh
UCODE=/path/to/ucode-wrapper python3 tests/service-recovery.py
ucode -L /absolute/path/to/luci-app-passwall/root/usr/share/ucode tests/reliability.uc
sudo env UCODE=/path/to/ucode-wrapper bash tests/routing.sh
sudo env ROUTING_TCP_WAY=tproxy UCODE=/path/to/ucode-wrapper bash tests/routing.sh
```


防火墙验收区分代理进程与 LAN 转发：首页在 fw4 表、forward 链、IPv4 forwarding 或已配置 NAT 区域的 MASQUERADE 缺失时单独显示警告。检查只读取系统规则，不自动重建或清空防火墙。`tests/firewall-health.uc` 覆盖这些状态。

`tests/routing.sh` 强制检查当前网络命名空间与宿主不同；它预置模拟 fw4 的 forward/NAT 表，验证 Passwall 启动、重载、停止后规则不变。生产设备排查禁止使用全局 `nft flush ruleset`；Passwall 的清理限定在自己管理的表、策略规则和有明确归属的兼容 hook 中。宿主内核的 nft 通过不代表设备内核也接受所有 mark 表达式，部署前还需设备的只读校验。

主核心托管回归：`UCODE=/path/to/ucode-wrapper python3 tests/core-service-ubus.py`。覆盖空成功响应、异步注册、空服务、缺少重启策略、停止状态及查询失败，失败实例会先注销。


DNS TTL 上限：`global_rules.dns_max_ttl` 可配置 60–86400 秒，未配置时为 3600 秒。生成的 Passwall dnsmasq 配置为未设置的上限提供默认值；保留通过 conf-file 引用的管理员上限以避免重复关键字，不覆盖这些引用文件中的值；保留配置中已有的更低上限，不抬高短 TTL 或零 TTL。可在“其他设置 → DNS cache policy”调整。此项不改变 nft 集合的 2 天超时，不等于逐答案 TTL 同步，也不覆盖绕开路由器 DNS 的客户端。SmartDNS 自身缓存仍由其配置管理。检查：`ucode -L /absolute/path/to/luci-app-passwall/root/usr/share/ucode tests/dns-policy.uc`。

## 独立 REALITY 客户端

安装本地 Rust `reality` 客户端到 `/usr/bin/reality` 后，节点类型列表会显示
`Reality (Rust)`。支持 VLESS REALITY、raw TCP、Vision 和 Chrome 指纹；
TCP REDIRECT/TProxy、UDP TProxy 及本地 TCP SOCKS5 都由该客户端处理。
Xray 不是这些节点的运行依赖。SS 节点继续由 shadowsocks-rust 处理。

订阅设置的 VLESS 使用类型可选择 `reality`，手动导入和订阅都会验证支持范围，
不支持的传输、额外加密、ECH、ML-DSA、finalmask 或代理链会被拒绝。
本后端不实现 Xray 的其他协议、高级内部路由及 HTTP 代理入口。
域名/IP 分流、国内直连、远端 DNS 和 UDP 端口策略仍由 Passwall、
nftables、dnsmasq 与 ChinaDNS 配合完成；不会清除用户已有的 UDP/443 阻断规则。

ChinaDNS 启动前会创建并填充它启动时读取的静态国家地址集合；
监听就绪后才切换 DNS。原生核心同主 Xray 核心一样受 procd 托管，
进程退出后重启。节点 URL 检测所用的随机数 API 也作为公共接口导出。

新增设备检查：

```sh
ucode tests/reality-config.uc
ucode tests/urltest-contract.uc
```

这两个测试需要本仓库的 ucode 模块可被加载。实际设备验收还应覆盖：
切换节点后立即解析和访问、REDIRECT/TProxy、透明 UDP 的出口地址、
订阅更新保持 Reality 类型、核心进程退出后的恢复，以及移除 Xray 后的运行状态。
