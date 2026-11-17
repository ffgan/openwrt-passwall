use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::time::Duration;

use passwall_tools::{convert, parse_subscription_userinfo, Probe};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("clash") => clash(args),
        Some("urltest") => urltest(args),
        Some("-h" | "--help") | None => {
            print_usage();
            ExitCode::SUCCESS
        }
        _ => {
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn clash(args: impl Iterator<Item = String>) -> ExitCode {
    let args: Vec<String> = args.collect();
    let Some(cmd) = args.first().map(String::as_str) else {
        print_usage();
        return ExitCode::from(2);
    };
    let mut input: Option<String> = None;
    let mut log: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                input = args.get(i).cloned();
            }
            "--log" => {
                i += 1;
                log = args.get(i).cloned();
            }
            _ => {
                print_usage();
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let raw = match read_input(input.as_deref()) {
        Ok(raw) => raw,
        Err(err) => {
            eprintln!("passwall-tools: {err}");
            return ExitCode::from(1);
        }
    };
    match cmd {
        "convert" => {
            let got = convert(&raw);
            write_log(log.as_deref(), &got.logs);
            print!("{body}", body = got.body);
            ExitCode::SUCCESS
        }
        "subinfo" => {
            if let Some(info) = parse_subscription_userinfo(&raw) {
                println!("{}", info.json());
            }
            ExitCode::SUCCESS
        }
        _ => {
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn urltest(args: impl Iterator<Item = String>) -> ExitCode {
    let args: Vec<String> = args.collect();
    let mut proxy = None;
    let mut url = None;
    let mut proxy_user = None;
    let mut connect_timeout = Duration::from_secs(3);
    let mut max_time = Duration::from_secs(5);
    let mut i = 0;
    while i < args.len() {
        let value = args.get(i + 1).cloned();
        match args[i].as_str() {
            "--proxy" => proxy = value,
            "--url" => url = value,
            "--proxy-user" => proxy_user = value,
            "--connect-timeout" => {
                if let Some(text) = value.as_deref() {
                    if let Ok(secs) = text.parse::<u64>() {
                        connect_timeout = Duration::from_secs(secs);
                    }
                }
            }
            "--max-time" => {
                if let Some(text) = value.as_deref() {
                    if let Ok(secs) = text.parse::<u64>() {
                        max_time = Duration::from_secs(secs);
                    }
                }
            }
            _ => {
                println!("0");
                return ExitCode::SUCCESS;
            }
        }
        i += 2;
    }
    let (Some(proxy), Some(url)) = (proxy, url) else {
        println!("0");
        return ExitCode::SUCCESS;
    };
    println!(
        "{}",
        Probe {
            proxy,
            proxy_user,
            url,
            connect_timeout,
            max_time,
        }
        .run()
    );
    ExitCode::SUCCESS
}

fn read_input(path: Option<&str>) -> io::Result<String> {
    match path {
        Some("-") | None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            Ok(buf)
        }
        Some(path) => fs::read_to_string(path),
    }
}

fn write_log(path: Option<&str>, logs: &[String]) {
    let text = if logs.is_empty() {
        String::new()
    } else {
        format!("{}\n", logs.join("\n"))
    };
    if let Some(path) = path {
        let _ = fs::write(path, text);
    } else {
        for line in logs {
            eprintln!("{line}");
        }
    }
}

fn print_usage() {
    let _ = writeln!(
        io::stderr(),
        "\
passwall-tools clash convert [--input FILE] [--log FILE]
passwall-tools clash subinfo [--input FILE]
passwall-tools urltest --proxy socks5h://HOST:PORT --url URL [--proxy-user USER:PASS]"
    );
}
