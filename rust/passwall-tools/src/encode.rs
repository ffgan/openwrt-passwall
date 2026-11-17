use indexmap::IndexMap;

use crate::value::{
    as_str, as_text, b64_value, base64, get, is_false, is_null, is_true, lua_or, to_json,
    to_number, truthy, urlencode, Map, Value,
};
use crate::yaml::parse_yaml;

pub struct Converted {
    pub body: String,
    pub logs: Vec<String>,
}

pub fn convert(raw: &str) -> Converted {
    let data = match parse_yaml(raw) {
        Ok(data) => data,
        Err(_) => {
            return Converted {
                body: raw.to_string(),
                logs: Vec::new(),
            }
        }
    };
    let Value::Map(_) = &data else {
        return Converted {
            body: raw.to_string(),
            logs: Vec::new(),
        };
    };
    let proxies = get(&data, "proxies");
    if is_null(proxies) || is_false(proxies) {
        return Converted {
            body: String::new(),
            logs: Vec::new(),
        };
    }
    let Value::Array(nodes) = proxies else {
        return Converted {
            body: String::new(),
            logs: Vec::new(),
        };
    };

    let mut logs = vec!["检测到 Clash 订阅，正在进行转换 ...".to_string()];
    let hosts = hosts_of(get(&data, "hosts"));
    let mut links = Vec::new();
    for node in nodes {
        if let Some(link) = encode_node(node, &hosts, &mut logs) {
            links.push(link);
        }
    }
    Converted {
        body: links.join("\n"),
        logs,
    }
}

fn hosts_of(hosts: &Value) -> IndexMap<String, String> {
    let mut out = IndexMap::new();
    let Value::Map(map) = hosts else { return out };
    for (key, value) in map {
        let Some(target) = as_str(value) else {
            continue;
        };
        if hostname(key) && hostname(target) {
            out.insert(key.clone(), target.to_string());
        }
    }
    out
}

fn encode_node(
    node: &Value,
    hosts: &IndexMap<String, String>,
    logs: &mut Vec<String>,
) -> Option<String> {
    let Value::Map(_) = node else { return None };
    if is_null(get(node, "type"))
        || is_false(get(node, "type"))
        || is_null(get(node, "name"))
        || is_false(get(node, "name"))
    {
        return None;
    }
    let mut node = node.clone();
    let server = as_str(get(&node, "server")).map(|s| s.to_string());
    if let (Some(server), Value::Map(map)) = (server, &mut node) {
        if let Some(redir) = hosts.get(&server) {
            map.insert("server".to_string(), Value::String(redir.clone()));
        }
    }
    let kind = as_text(get(&node, "type"));
    let encoded = match kind.as_str() {
        "vless" => encode_vless(&node, hosts),
        "trojan" => encode_trojan(&node, hosts),
        "vmess" => encode_vmess(&node, hosts),
        "ss" => encode_ss(&node),
        "hysteria" => Ok(encode_hysteria(&node)),
        "hysteria2" => Ok(encode_hysteria2(&node)),
        "tuic" => Ok(encode_tuic(&node)),
        "anytls" => encode_anytls(&node, hosts),
        "ssr" => Ok(encode_ssr(&node)),
        "snell" => encode_snell(&node),
        _ => {
            logs.push(format!(
                "订阅转换 → 丢弃不支持的节点：{}，节点类型：{kind}",
                as_text(get(&node, "name"))
            ));
            return None;
        }
    };
    match encoded {
        Ok(link) => Some(link),
        Err(msg) => {
            logs.push(msg);
            None
        }
    }
}

struct Common {
    server: String,
    port: Value,
    name: Value,
    security: Value,
    pbk: Value,
    sid: Value,
    sni: Value,
    fp: Value,
    pcs: Value,
    insecure: bool,
    alpn: Value,
    ech: Value,
    net: String,
    host: Value,
    path: Value,
    service_name: Value,
    mode: Value,
    extra: Value,
}

fn build_common(node: &Value, hosts: &IndexMap<String, String>) -> Common {
    let net = if is_null(get(node, "network")) || is_false(get(node, "network")) {
        "tcp".to_string()
    } else {
        as_text(get(node, "network"))
    };
    let mut security = Value::Null;
    let mut pbk = Value::Null;
    let mut sid = Value::Null;
    if truthy(get(node, "reality-opts")) {
        security = Value::String("reality".into());
        pbk = get(get(node, "reality-opts"), "public-key").clone();
        sid = get(get(node, "reality-opts"), "short-id").clone();
    } else if truthy(get(node, "tls")) {
        security = Value::String("tls".into());
    }
    let sni = lua_or(get(node, "servername"), get(node, "sni")).clone();
    let fp = get(node, "client-fingerprint").clone();
    let pcs = get(node, "fingerprint").clone();
    let insecure = is_true(get(node, "skip-cert-verify"));
    let alpn = build_alpn(get(node, "alpn"));
    let ech = ech_of(get(node, "ech-opts"));

    let mut host = Value::Null;
    let mut path = Value::Null;
    let mut service_name = Value::Null;
    let mut mode = Value::Null;
    let mut extra = Value::Null;

    if net == "ws" {
        let opts = get(node, "ws-opts");
        if truthy(opts) {
            path = if is_null(get(opts, "path")) || is_false(get(opts, "path")) {
                Value::String("/".into())
            } else {
                get(opts, "path").clone()
            };
            let ed = get(opts, "max-early-data");
            let eh = get(opts, "early-data-header-name");
            if !is_null(ed) && !is_false(ed) {
                path = Value::String(format!("{}?ed={}", as_text(&path), as_text(ed)));
            }
            if !is_null(eh) && !is_false(eh) {
                let current = as_text(&path);
                let sep = if current.contains('?') {
                    "&eh="
                } else {
                    "?eh="
                };
                path = Value::String(format!("{current}{sep}{}", as_text(eh)));
            }
            host = get(get(opts, "headers"), "Host").clone();
        }
    } else if net == "grpc" {
        let opts = get(node, "grpc-opts");
        if truthy(opts) {
            service_name = get(opts, "grpc-service-name").clone();
        }
    } else if net == "http" {
        let opts = get(node, "http-opts");
        if truthy(opts) {
            let header_host = get(get(opts, "headers"), "Host");
            host = lua_or(first_of(get(opts, "host")), first_of(header_host)).clone();
            path = first_of(get(opts, "path")).clone();
        }
    } else if net == "h2" {
        let opts = get(node, "h2-opts");
        if truthy(opts) {
            host = first_of(get(opts, "host")).clone();
            path = get(opts, "path").clone();
        }
    } else if net == "xhttp" {
        if let Some(rendered) = xhttp_extra(node, hosts) {
            host = rendered.0;
            path = rendered.1;
            mode = rendered.2;
            extra = rendered.3;
        }
    }

    Common {
        server: host_format(get(node, "server")),
        port: get(node, "port").clone(),
        name: get(node, "name").clone(),
        security,
        pbk,
        sid,
        sni,
        fp,
        pcs,
        insecure,
        alpn,
        ech,
        net,
        host,
        path,
        service_name,
        mode,
        extra,
    }
}

fn xhttp_extra(
    node: &Value,
    hosts: &IndexMap<String, String>,
) -> Option<(Value, Value, Value, Value)> {
    let opts = get(node, "xhttp-opts");
    if !truthy(opts) {
        return None;
    }
    let host = get(opts, "host").clone();
    let path = get(opts, "path").clone();
    let mode = get(opts, "mode").clone();
    let mut extra = Map::new();
    if truthy(get(opts, "headers")) {
        extra.insert("headers".into(), get(opts, "headers").clone());
    }
    if truthy(get(opts, "x-padding-bytes")) {
        extra.insert("xPaddingBytes".into(), get(opts, "x-padding-bytes").clone());
    }
    if !is_null(get(opts, "no-grpc-header")) {
        extra.insert("noGRPCHeader".into(), get(opts, "no-grpc-header").clone());
    }
    if truthy(get(opts, "sc-max-each-post-bytes")) {
        extra.insert(
            "scMaxEachPostBytes".into(),
            get(opts, "sc-max-each-post-bytes").clone(),
        );
    }
    if truthy(get(opts, "sc-min-posts-interval-ms")) {
        extra.insert(
            "scMinPostsIntervalMs".into(),
            get(opts, "sc-min-posts-interval-ms").clone(),
        );
    }
    if truthy(get(opts, "reuse-settings")) {
        let r = get(opts, "reuse-settings");
        let mut xmux = Map::new();
        if truthy(get(r, "max-concurrency")) {
            xmux.insert("maxConcurrency".into(), get(r, "max-concurrency").clone());
        }
        if truthy(get(r, "max-connections")) {
            if let Some(n) = to_number(get(r, "max-connections")) {
                xmux.insert("maxConnections".into(), n);
            }
        }
        if truthy(get(r, "c-max-reuse-times")) {
            if let Some(n) = to_number(get(r, "c-max-reuse-times")) {
                xmux.insert("cMaxReuseTimes".into(), n);
            }
        }
        if truthy(get(r, "h-max-request-times")) {
            xmux.insert(
                "hMaxRequestTimes".into(),
                get(r, "h-max-request-times").clone(),
            );
        }
        if truthy(get(r, "h-max-reusable-secs")) {
            xmux.insert(
                "hMaxReusableSecs".into(),
                get(r, "h-max-reusable-secs").clone(),
            );
        }
        if truthy(get(r, "h-keep-alive-period")) {
            if let Some(n) = to_number(get(r, "h-keep-alive-period")) {
                xmux.insert("hKeepAlivePeriod".into(), n);
            }
        }
        if !xmux.is_empty() {
            extra.insert("xmux".into(), Value::Map(xmux));
        }
    }
    if truthy(get(opts, "download-settings")) {
        extra.insert(
            "downloadSettings".into(),
            download_settings(get(opts, "download-settings"), hosts),
        );
    }
    let extra = if extra.is_empty() {
        Value::Null
    } else {
        Value::String(to_json(&Value::Map(extra)))
    };
    Some((host, path, mode, extra))
}

fn download_settings(d: &Value, hosts: &IndexMap<String, String>) -> Value {
    let mut ds = Map::new();
    if truthy(get(d, "server")) {
        let server = as_text(get(d, "server"));
        let address = hosts.get(&server).cloned().unwrap_or(server);
        ds.insert("address".into(), Value::String(address));
    }
    if truthy(get(d, "port")) {
        ds.insert("port".into(), get(d, "port").clone());
    }
    ds.insert("network".into(), Value::String("xhttp".into()));
    if truthy(get(d, "tls")) {
        ds.insert("security".into(), Value::String("tls".into()));
        let mut tls = Map::new();
        if truthy(get(d, "servername")) {
            tls.insert("serverName".into(), get(d, "servername").clone());
        }
        if is_true(get(d, "skip-cert-verify")) {
            tls.insert("allowInsecure".into(), Value::Bool(true));
        }
        if truthy(get(d, "client-fingerprint")) {
            tls.insert("fingerprint".into(), get(d, "client-fingerprint").clone());
        }
        if truthy(get(d, "fingerprint")) {
            tls.insert("pinnedPeerCertSha256".into(), get(d, "fingerprint").clone());
        }
        if truthy(get(d, "alpn")) {
            tls.insert("alpn".into(), get(d, "alpn").clone());
        }
        ds.insert("tlsSettings".into(), Value::Map(tls));
    }
    let mut xs = Map::new();
    if truthy(get(d, "path")) {
        xs.insert("path".into(), get(d, "path").clone());
    }
    if truthy(get(d, "host")) {
        xs.insert("host".into(), get(d, "host").clone());
    }
    if !xs.is_empty() {
        ds.insert("xhttpSettings".into(), Value::Map(xs));
    }
    Value::Map(ds)
}

fn ech_of(opts: &Value) -> Value {
    if !(truthy(opts) && is_true(get(opts, "enable"))) {
        return Value::Null;
    }
    if truthy(get(opts, "query-server-name")) {
        return Value::String(format!(
            "{}+https://223.5.5.5/dns-query",
            as_text(get(opts, "query-server-name"))
        ));
    }
    if truthy(get(opts, "config")) {
        return get(opts, "config").clone();
    }
    Value::Null
}

fn build_alpn(alpn: &Value) -> Value {
    if is_null(alpn) || is_false(alpn) {
        return Value::Null;
    }
    let mut seen = IndexMap::<String, ()>::new();
    match alpn {
        Value::Array(items) => {
            for item in items {
                if !is_null(item) && !is_false(item) {
                    seen.insert(as_text(item), ());
                }
            }
        }
        other => {
            seen.insert(as_text(other), ());
        }
    }
    let picked: Vec<&str> = ["h3", "h2", "http/1.1"]
        .into_iter()
        .filter(|v| seen.contains_key(*v))
        .collect();
    if picked.is_empty() {
        Value::Null
    } else {
        Value::String(picked.join(","))
    }
}

fn first_of(v: &Value) -> &Value {
    match v {
        Value::Array(items) => items.first().unwrap_or(&Value::Null),
        other => other,
    }
}

fn push_param(params: &mut Vec<String>, key: &str, value: &Value, encode: bool) {
    if is_null(value) || is_false(value) {
        return;
    }
    let text = as_text(value);
    if encode {
        params.push(format!("{key}={}", urlencode(&text)));
    } else {
        params.push(format!("{key}={text}"));
    }
}

fn finish_link(link: &str, params: &[String], name: &Value) -> String {
    let mut link = link.to_string();
    if !params.is_empty() {
        link.push('?');
        link.push_str(&params.join("&"));
    }
    let name = if is_null(name) || is_false(name) {
        String::new()
    } else {
        as_text(name)
    };
    format!("{link}#{}", urlencode(&name))
}

fn tls_params(params: &mut Vec<String>, o: &Common, insecure_key: &str) {
    if !is_null(&o.security) && !is_false(&o.security) {
        params.push(format!("security={}", as_text(&o.security)));
    }
    push_param(params, "pbk", &o.pbk, true);
    push_param(params, "sid", &o.sid, true);
    push_param(params, "sni", &o.sni, true);
    push_param(params, "fp", &o.fp, true);
    push_param(params, "alpn", &o.alpn, true);
    push_param(params, "ech", &o.ech, true);
    push_param(params, "pcs", &o.pcs, true);
    params.push(format!(
        "{insecure_key}={}",
        if o.insecure { "1" } else { "0" }
    ));
}

fn encode_vless(node: &Value, hosts: &IndexMap<String, String>) -> Result<String, String> {
    let o = build_common(node, hosts);
    let link = format!(
        "vless://{}@{}:{}",
        as_text(get(node, "uuid")),
        o.server,
        as_text(&o.port)
    );
    let mut params = Vec::new();
    if as_str(get(node, "flow")).is_some_and(|flow| flow.starts_with("xtls-")) {
        params.push(format!(
            "flow={}",
            urlencode(as_str(get(node, "flow")).unwrap_or(""))
        ));
    }
    if truthy(get(node, "encryption")) {
        params.push(format!(
            "encryption={}",
            urlencode(&as_text(get(node, "encryption")))
        ));
    }
    tls_params(&mut params, &o, "allowInsecure");
    params.push(format!("type={}", o.net));
    push_param(&mut params, "host", &o.host, true);
    push_param(&mut params, "path", &o.path, true);
    push_param(&mut params, "serviceName", &o.service_name, true);
    push_param(&mut params, "mode", &o.mode, true);
    push_param(&mut params, "extra", &o.extra, true);
    Ok(finish_link(&link, &params, &o.name))
}

fn encode_trojan(node: &Value, hosts: &IndexMap<String, String>) -> Result<String, String> {
    let o = build_common(node, hosts);
    let link = format!(
        "trojan://{}@{}:{}",
        as_text(get(node, "password")),
        o.server,
        as_text(&o.port)
    );
    let mut params = Vec::new();
    tls_params(&mut params, &o, "allowInsecure");
    params.push(format!("type={}", o.net));
    push_param(&mut params, "host", &o.host, true);
    push_param(&mut params, "path", &o.path, true);
    push_param(&mut params, "serviceName", &o.service_name, true);
    Ok(finish_link(&link, &params, &o.name))
}

fn encode_vmess(node: &Value, hosts: &IndexMap<String, String>) -> Result<String, String> {
    let o = build_common(node, hosts);
    let mut obj = Map::new();
    let mut put = |key: &str, value: Value| {
        if !is_null(&value) {
            obj.insert(key.to_string(), value);
        }
    };
    put("v", Value::String("2".into()));
    put("ps", o.name.clone());
    put("add", get(node, "server").clone());
    put("port", Value::String(as_text(&o.port)));
    put("id", get(node, "uuid").clone());
    let aid = if is_null(get(node, "alterId")) {
        Value::Int(0)
    } else {
        get(node, "alterId").clone()
    };
    put("aid", Value::String(as_text(&aid)));
    put("net", Value::String(o.net.clone()));
    put("security", get(node, "cipher").clone());
    put("scy", get(node, "cipher").clone());
    put("type", Value::String("none".into()));
    put(
        "host",
        Value::String(if is_null(&o.host) || is_false(&o.host) {
            String::new()
        } else {
            as_text(&o.host)
        }),
    );
    let path = if o.net == "grpc" {
        &o.service_name
    } else {
        &o.path
    };
    put(
        "path",
        Value::String(if is_null(path) || is_false(path) {
            String::new()
        } else {
            as_text(path)
        }),
    );
    put(
        "tls",
        Value::String(if as_str(&o.security) == Some("tls") {
            "tls".into()
        } else {
            String::new()
        }),
    );
    put("sni", o.sni.clone());
    put("alpn", o.alpn.clone());
    put("fp", o.fp.clone());
    put("ech", o.ech.clone());
    put("pcs", o.pcs.clone());
    put(
        "insecure",
        Value::String(if o.insecure { "1".into() } else { "0".into() }),
    );
    put(
        "tfo",
        Value::String(
            if !is_null(get(node, "tfo")) && !is_false(get(node, "tfo")) {
                "1".into()
            } else {
                "0".into()
            },
        ),
    );
    Ok(format!(
        "vmess://{}",
        base64(to_json(&Value::Map(obj)).as_bytes())
    ))
}

fn encode_ss(node: &Value) -> Result<String, String> {
    const METHODS: &[&str] = &[
        "none",
        "aes-128-gcm",
        "aes-192-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "aes-128-cfb",
        "aes-192-cfb",
        "aes-256-cfb",
        "rc4-md5",
        "chacha20-ietf",
        "xchacha20",
    ];
    let cipher = if is_null(get(node, "cipher")) || is_false(get(node, "cipher")) {
        String::new()
    } else {
        as_text(get(node, "cipher"))
    };
    let name = if is_null(get(node, "name")) || is_false(get(node, "name")) {
        String::new()
    } else {
        as_text(get(node, "name"))
    };
    if !METHODS.contains(&cipher.as_str()) {
        return Err(format!(
            "订阅转换 → 丢弃 SS 节点：{name}，因 Core 不支持 {cipher} 加密方式"
        ));
    }
    let userinfo = format!("{cipher}:{}", as_text(get(node, "password")));
    let base = format!(
        "{userinfo}@{}:{}",
        host_format(get(node, "server")),
        as_text(get(node, "port"))
    );
    let link = format!("ss://{}", base64(base.as_bytes()));
    let mut params = Vec::new();
    if truthy(get(node, "udp")) {
        params.push("udp=1".to_string());
    }
    if truthy(get(node, "udp-over-tcp")) {
        params.push("uot=1".to_string());
    }
    if truthy(get(node, "plugin")) {
        let mut plugin = as_text(get(node, "plugin"));
        if plugin == "obfs" {
            plugin = "obfs-local".to_string();
        }
        if plugin == "shadow-tls" {
            let opts = lua_or(get(node, "plugin-opts"), &Value::Map(Map::new())).clone();
            let packed = b64_value(&Value::String(to_json(&opts)));
            params.push(format!("shadow-tls={}", urlencode(&packed)));
        } else if plugin == "obfs-local" || plugin == "v2ray-plugin" {
            let popts = get(node, "plugin-opts");
            let empty = Value::Map(Map::new());
            let popts = if let Value::Map(_) = popts {
                popts
            } else {
                &empty
            };
            let mut opts = Vec::new();
            if let Value::Map(map) = popts {
                for (key, val) in map {
                    let mut key = key.clone();
                    let mut val = val.clone();
                    if plugin == "obfs-local" {
                        if key == "mode" {
                            key = "obfs".to_string();
                        }
                        if key == "host" {
                            key = "obfs-host".to_string();
                        }
                    } else if plugin == "v2ray-plugin" {
                        if key == "mode" && as_str(&val) == Some("websocket") {
                            val = Value::Null;
                        } else if matches!(val, Value::Bool(_)) {
                            if is_true(&val) {
                                opts.push(key.clone());
                            }
                            val = Value::Null;
                        }
                    }
                    if !is_null(&val) {
                        if matches!(val, Value::Bool(_)) {
                            val = Value::String(if is_true(&val) {
                                "1".into()
                            } else {
                                "0".into()
                            });
                        }
                        opts.push(format!("{key}={}", as_text(&val)));
                    }
                }
            }
            if !opts.is_empty() {
                plugin = format!("{plugin};{}", opts.join(";"));
            }
            params.push(format!("plugin={}", urlencode(&plugin)));
        } else {
            return Err(format!(
                "订阅转换 → 丢弃 SS 节点：{name}，因 Core 不支持 {plugin} 插件"
            ));
        }
    }
    Ok(finish_link(&link, &params, get(node, "name")))
}

fn encode_hysteria(node: &Value) -> String {
    let link = format!(
        "hysteria://{}:{}",
        host_format(get(node, "server")),
        text_or_empty(get(node, "port"))
    );
    let mut params = Vec::new();
    push_param(&mut params, "auth", get(node, "auth-str"), false);
    push_param(&mut params, "mport", get(node, "ports"), false);
    push_param(&mut params, "obfsParam", get(node, "obfs"), false);
    push_param(&mut params, "sni", get(node, "sni"), false);
    push_param(&mut params, "upmbps", get(node, "up"), false);
    push_param(&mut params, "downmbps", get(node, "down"), false);
    if truthy(get(node, "skip-cert-verify")) {
        params.push("insecure=1".into());
    }
    push_param(&mut params, "pinSHA256", get(node, "fingerprint"), true);
    if truthy(get(node, "alpn")) {
        let alpn = build_alpn(get(node, "alpn"));
        params.push(format!("alpn={}", urlencode(&as_text(&alpn))));
    }
    finish_link(&link, &params, get(node, "name"))
}

fn encode_hysteria2(node: &Value) -> String {
    let link = format!(
        "hysteria2://{}@{}:{}",
        text_or_empty(get(node, "password")),
        host_format(get(node, "server")),
        text_or_empty(get(node, "port"))
    );
    let mut params = Vec::new();
    push_param(&mut params, "mport", get(node, "ports"), true);
    push_param(&mut params, "obfs", get(node, "obfs"), false);
    push_param(
        &mut params,
        "obfs-password",
        get(node, "obfs-password"),
        false,
    );
    push_param(
        &mut params,
        "minPacketSize",
        get(node, "obfs-min-packet-size"),
        false,
    );
    push_param(
        &mut params,
        "maxPacketSize",
        get(node, "obfs-max-packet-size"),
        false,
    );
    push_param(&mut params, "upmbps", get(node, "up"), false);
    push_param(&mut params, "downmbps", get(node, "down"), false);
    push_param(&mut params, "sni", get(node, "sni"), true);
    if truthy(get(node, "skip-cert-verify")) {
        params.push("insecure=1".into());
    }
    push_param(&mut params, "pinSHA256", get(node, "fingerprint"), true);
    finish_link(&link, &params, get(node, "name"))
}

fn encode_tuic(node: &Value) -> String {
    let link = format!(
        "tuic://{}:{}@{}:{}",
        as_text(get(node, "uuid")),
        as_text(get(node, "password")),
        host_format(get(node, "server")),
        as_text(get(node, "port"))
    );
    let mut params = Vec::new();
    if truthy(get(node, "congestion-controller")) {
        params.push(format!(
            "congestion_control={}",
            as_text(get(node, "congestion-controller"))
        ));
    }
    if truthy(get(node, "alpn")) {
        params.push(format!(
            "alpn={}",
            urlencode(&as_text(&build_alpn(get(node, "alpn"))))
        ));
    }
    push_param(&mut params, "sni", get(node, "sni"), true);
    if truthy(get(node, "disable-sni")) {
        params.push("disable_sni=1".into());
    }
    if truthy(get(node, "skip-cert-verify")) {
        params.push("allowInsecure=1".into());
    }
    if truthy(get(node, "udp-relay-mode")) {
        params.push(format!(
            "udp_relay_mode={}",
            as_text(get(node, "udp-relay-mode"))
        ));
    }
    push_param(&mut params, "pcs", get(node, "fingerprint"), true);
    finish_link(&link, &params, get(node, "name"))
}

fn encode_anytls(node: &Value, hosts: &IndexMap<String, String>) -> Result<String, String> {
    let err = if truthy(get(node, "shadow-tls-opts")) {
        Some("ShadowTLS")
    } else if truthy(get(node, "restls-opts")) {
        Some("ResTLS")
    } else if truthy(get(node, "jls-opts")) {
        Some("JLS")
    } else {
        None
    };
    if let Some(err) = err {
        let name = text_or_empty(get(node, "name"));
        return Err(format!(
            "订阅转换 → 丢弃 AnyTLS 节点：{name}，因 Sing-Box 不支持 AnyTLS + {err}"
        ));
    }
    let o = build_common(node, hosts);
    let link = format!(
        "anytls://{}@{}:{}",
        text_or_empty(get(node, "password")),
        host_format(get(node, "server")),
        as_text(get(node, "port"))
    );
    let mut params = Vec::new();
    if !is_null(&o.security) && !is_false(&o.security) {
        params.push(format!("security={}", as_text(&o.security)));
    }
    push_param(&mut params, "pbk", &o.pbk, true);
    push_param(&mut params, "sid", &o.sid, true);
    push_param(&mut params, "sni", &o.sni, true);
    push_param(&mut params, "alpn", &o.alpn, true);
    push_param(&mut params, "fp", &o.fp, true);
    push_param(&mut params, "ech", &o.ech, true);
    push_param(&mut params, "pcs", &o.pcs, true);
    params.push(format!("insecure={}", if o.insecure { "1" } else { "0" }));
    Ok(finish_link(&link, &params, &o.name))
}

fn encode_ssr(node: &Value) -> String {
    let link = format!(
        "{}:{}:{}:{}:{}:{}",
        host_format(get(node, "server")),
        as_text(get(node, "port")),
        text_or_empty(get(node, "protocol")),
        text_or_empty(get(node, "cipher")),
        text_or_empty(get(node, "obfs")),
        b64_value(get(node, "password"))
    );
    let mut params = Vec::new();
    if truthy(get(node, "obfs-param")) {
        params.push(format!("obfsparam={}", b64_value(get(node, "obfs-param"))));
    }
    if truthy(get(node, "protocol-param")) {
        params.push(format!(
            "protoparam={}",
            b64_value(get(node, "protocol-param"))
        ));
    }
    params.push(format!("remarks={}", b64_value(get(node, "name"))));
    format!(
        "ssr://{}",
        base64(format!("{link}?{}", params.join("&")).as_bytes())
    )
}

fn encode_snell(node: &Value) -> Result<String, String> {
    let name = text_or_empty(get(node, "name"));
    let obfs = get(node, "obfs-opts");
    if let Some(mode) = snell_obfs_error(obfs) {
        return Err(format!(
            "订阅转换 → 丢弃 Snell 节点：{name}，因 Sing-Box 不支持 Snell + {mode}"
        ));
    }
    let mut version = 4.0f64;
    if !is_null(get(node, "version")) && !is_false(get(node, "version")) {
        version = match to_number(get(node, "version")) {
            Some(Value::Int(n)) => n as f64,
            Some(Value::Float(n)) => n,
            _ => 4.0,
        };
    }
    if version == 5.0 {
        version = 4.0;
    }
    if version < 4.0 {
        return Err(format!(
            "订阅转换 → 丢弃 Snell 节点：{name}，因 Sing-Box 不支持 Snell 版本小于 4"
        ));
    }
    let version_text = if version.fract() == 0.0 {
        format!("{}", version as i64)
    } else {
        format!("{version}")
    };
    let link = format!(
        "snell://{}:{}",
        host_format(get(node, "server")),
        as_text(get(node, "port"))
    );
    let mut params = Vec::new();
    if truthy(get(node, "psk")) {
        params.push(format!("psk={}", urlencode(&as_text(get(node, "psk")))));
    }
    params.push(format!("version={version_text}"));
    if truthy(obfs) && as_text(get(obfs, "mode")) == "http" {
        params.push("obfs=http".into());
        if truthy(get(obfs, "host")) {
            params.push(format!(
                "obfs-host={}",
                urlencode(&as_text(get(obfs, "host")))
            ));
        }
    }
    params.push(format!(
        "reuse={}",
        if truthy(get(node, "reuse")) { "1" } else { "0" }
    ));
    Ok(finish_link(&link, &params, get(node, "name")))
}

fn snell_obfs_error(obfs: &Value) -> Option<String> {
    if !truthy(obfs) {
        return None;
    }
    let mode = get(obfs, "mode");
    let text = as_text(mode);
    if text == "http" || text == "none" || !truthy(mode) {
        return None;
    }
    Some(text)
}

fn text_or_empty(v: &Value) -> String {
    if is_null(v) || is_false(v) {
        String::new()
    } else {
        as_text(v)
    }
}

fn host_format(host: &Value) -> String {
    if is_null(host) || is_false(host) {
        return String::new();
    }
    let original = as_text(host);
    let mut inner = original.clone();
    if let Some(start) = original.find('[') {
        if let Some(end) = original[start + 1..].rfind(']') {
            let body = &original[start + 1..start + 1 + end];
            if !body.is_empty() {
                inner = body.to_string();
            }
        }
    }
    if ip6addr(&inner) {
        format!("[{inner}]")
    } else {
        original
    }
}

fn hostname(val: &str) -> bool {
    if val.is_empty() || val.len() >= 254 {
        return false;
    }
    let bytes = val.as_bytes();
    if bytes.iter().all(|c| c.is_ascii_alphabetic() || *c == b'_') {
        return true;
    }
    if bytes.len() < 2 {
        return false;
    }
    let first_ok = bytes[0].is_ascii_alphanumeric() || bytes[0] == b'_';
    let last_ok = bytes[bytes.len() - 1].is_ascii_alphanumeric();
    let mid_ok = bytes[1..bytes.len() - 1]
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'%' | b'.' | b'-'));
    let mixed = bytes.iter().any(|c| !c.is_ascii_digit() && *c != b'.');
    first_ok && last_ok && mid_ok && mixed
}

fn ip4addr(val: &str) -> bool {
    let parts: Vec<&str> = val.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|part| {
        !part.is_empty()
            && part.len() <= 3
            && part.bytes().all(|c| c.is_ascii_digit())
            && part.parse::<u16>().ok().is_some_and(|n| n <= 255)
    })
}

fn ip6_side(s: &str, out: &mut Vec<u8>) -> bool {
    if s.is_empty() {
        return true;
    }
    let parts: Vec<&str> = s.split(':').collect();
    for (idx, tok) in parts.iter().enumerate() {
        if tok.is_empty() {
            return false;
        }
        if tok.contains('.') {
            if idx != parts.len() - 1 || !ip4addr(tok) {
                return false;
            }
            out.push(1);
            out.push(1);
        } else {
            if tok.len() > 4 || !tok.bytes().all(|c| c.is_ascii_hexdigit()) {
                return false;
            }
            out.push(1);
        }
    }
    true
}

fn ip6addr(val: &str) -> bool {
    if val.is_empty() {
        return false;
    }
    let s = val.split('%').next().unwrap_or("");
    if s.is_empty() || s.match_indices("::").nth(1).is_some() {
        return false;
    }
    let (left, right, dbl) = if let Some(i) = s.find("::") {
        (&s[..i], &s[i + 2..], true)
    } else {
        (s, "", false)
    };
    let mut left_n = Vec::new();
    let mut right_n = Vec::new();
    if !ip6_side(left, &mut left_n) || !ip6_side(right, &mut right_n) {
        return false;
    }
    let count = left_n.len() + right_n.len();
    if dbl {
        count < 8
    } else {
        count == 8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::base64;

    fn ss_yaml() -> &'static str {
        "proxies:\n  - name: a\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-256-gcm\n    password: secret\n    udp: true\n"
    }

    #[test]
    fn shadowsocks_link() {
        let got = convert(ss_yaml());
        let payload = format!("aes-256-gcm:secret@1.2.3.4:8388");
        assert_eq!(
            got.body,
            format!("ss://{}?udp=1#a", base64(payload.as_bytes()))
        );
        assert_eq!(
            got.logs,
            vec!["检测到 Clash 订阅，正在进行转换 ...".to_string()]
        );
    }

    #[test]
    fn vless_ws() {
        let raw = "\
proxies:
  - name: n
    type: vless
    server: ex.com
    port: 443
    uuid: uuid
    tls: true
    servername: sni.example
    client-fingerprint: chrome
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: h.example
";
        let got = convert(raw);
        assert_eq!(
            got.body,
            "vless://uuid@ex.com:443?security=tls&sni=sni.example&fp=chrome&allowInsecure=0&type=ws&host=h.example&path=%2Fws#n"
        );
    }

    #[test]
    fn vmess_json_shape() {
        let raw = "\
proxies:
  - name: n
    type: vmess
    server: 1.2.3.4
    port: 443
    uuid: u
    alterId: 0
    cipher: auto
";
        let got = convert(raw);
        let b64 = got.body.trim_start_matches("vmess://");
        let bytes = base64_decode(b64);
        let json = String::from_utf8(bytes).unwrap();
        assert_eq!(
            json,
            r#"{"v":"2","ps":"n","add":"1.2.3.4","port":"443","id":"u","aid":"0","net":"tcp","security":"auto","scy":"auto","type":"none","host":"","path":"","tls":"","insecure":"0","tfo":"0"}"#
        );
    }

    #[test]
    fn drops_unknown_and_bad_cipher() {
        let raw = "\
proxies:
  - name: bad
    type: ss
    server: 1.2.3.4
    port: 1
    cipher: rc4
    password: x
  - name: wire
    type: wireguard
    server: 1.2.3.4
";
        let got = convert(raw);
        assert_eq!(got.body, "");
        assert!(got.logs[1].contains("丢弃 SS 节点：bad"));
        assert!(got.logs[2].contains("节点类型：wireguard"));
    }

    #[test]
    fn non_clash_is_returned() {
        let raw = "ss://already-a-link";
        let got = convert(raw);
        assert_eq!(got.body, raw);
        assert!(got.logs.is_empty());
    }

    #[test]
    fn broken_yaml_is_returned() {
        let raw = "proxies: [\n";
        assert_eq!(convert(raw).body, raw);
    }

    #[test]
    fn missing_proxies_is_empty() {
        let got = convert("foo: 1\n");
        assert_eq!(got.body, "");
        assert!(got.logs.is_empty());
    }

    #[test]
    fn host_rewrite_and_ipv6() {
        let raw = "\
hosts:
  edge.example: origin.example
proxies:
  - name: v6
    type: ss
    server: 2001:db8::1
    port: 8388
    cipher: aes-128-gcm
    password: p
  - name: redir
    type: ss
    server: edge.example
    port: 8388
    cipher: aes-128-gcm
    password: p
";
        let got = convert(raw);
        let lines: Vec<&str> = got.body.split('\n').collect();
        assert!(lines[0].starts_with(&format!(
            "ss://{}",
            base64(b"aes-128-gcm:p@[2001:db8::1]:8388")
        )));
        assert!(lines[1].contains(&base64(b"aes-128-gcm:p@origin.example:8388")));
    }

    #[test]
    fn obfs_plugin_renames_keys() {
        let raw = "\
proxies:
  - name: a
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: secret
    plugin: obfs
    plugin-opts:
      mode: tls
      host: ex.com
";
        let got = convert(raw);
        assert!(
            got.body
                .contains("plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dex.com#a"),
            "{}",
            got.body
        );
    }

    #[test]
    fn hysteria2_and_snell() {
        let raw = "\
proxies:
  - name: hy
    type: hysteria2
    server: hy.example
    port: 443
    password: pw
    sni: sni.example
    skip-cert-verify: true
  - name: sn
    type: snell
    server: sn.example
    port: 44046
    psk: secret
    version: 5
    obfs-opts:
      mode: http
      host: www.example
";
        let got = convert(raw);
        let lines: Vec<&str> = got.body.split('\n').collect();
        assert_eq!(
            lines[0],
            "hysteria2://pw@hy.example:443?sni=sni.example&insecure=1#hy"
        );
        assert_eq!(
            lines[1],
            "snell://sn.example:44046?psk=secret&version=4&obfs=http&obfs-host=www.example&reuse=0#sn"
        );
    }

    fn base64_decode(text: &str) -> Vec<u8> {
        fn val(c: u8) -> u8 {
            match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => 0,
            }
        }
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i + 4 <= bytes.len() {
            let n = ((val(bytes[i]) as u32) << 18)
                | ((val(bytes[i + 1]) as u32) << 12)
                | ((val(bytes[i + 2]) as u32) << 6)
                | val(bytes[i + 3]) as u32;
            out.push((n >> 16) as u8);
            if bytes[i + 2] != b'=' {
                out.push((n >> 8) as u8);
            }
            if bytes[i + 3] != b'=' {
                out.push(n as u8);
            }
            i += 4;
        }
        out
    }
}
