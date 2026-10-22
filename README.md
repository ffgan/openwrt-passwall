# luci-app-passwall

OpenWrt 25.12 及更新版本上的 PassWall。透明代理走 **firewall4 / nftables**，软件包用 **apk** 安装，Web 界面是 LuCI JavaScript 视图，服务逻辑是 ucode。

## 布局

| 路径 | 作用 |
| --- | --- |
| `luci-app-passwall/htdocs/` | LuCI 页面。公共样式在 `passwall.css`，运行状态缓存解析在 `runtime.js`。 |
| `luci-app-passwall/root/usr/libexec/passwall/` | 给 procd、热插拔和计划任务调用的 ucode 入口。 |
| `luci-app-passwall/root/usr/share/ucode/passwall/` | 可复用的服务、订阅、nftables 和协议配置库。 |
| `luci-app-passwall/root/usr/share/rpcd/ucode/luci.passwall` | LuCI 通过 ubus 调用的接口。 |

运行中的变量写在 `/tmp/etc/passwall/var`。新进程把它写成 JSON 对象；启动时仍能读旧的 `KEY='value'` 行，下一次写入会换成 JSON。进程匹配直接读 `/proc/<pid>/cmdline`，不再调用 `busybox pgrep`。

节点列表和分流规则的拖动排序由 `sortable.js` 完成，使用指针事件，不再附带 SortableJS。

## 编译

在官方 `feeds.conf.default` 顶部加入：

```
src-git passwall_packages https://github.com/Openwrt-Passwall/openwrt-passwall-packages.git;main
src-git passwall_luci https://github.com/ffgan/openwrt-passwall.git;main
```

然后执行 `./scripts/feeds update -a` 和 `./scripts/feeds install -a`，在 menuconfig 里选择 `luci-app-passwall`。

设备上安装编译产物：

```shell
apk add --allow-untrusted /path/to/luci-app-passwall.apk
```

## Xray 证书

自 2026 年 6 月 1 日起，Xray 不再接受用 `allowInsecure` 跳过证书校验。自签证书需要 `pinnedPeerCertSha256`（分享链接里的 `pcs`）。没有这个值时，改用 Sing-box。

## 检查

```shell
node tests/check.mjs
```

检查 LuCI 脚本语法、JSON/旧缓存解析，以及表格拖动排序。
