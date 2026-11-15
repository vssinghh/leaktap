use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Spawns a zero-root background poller watching outbound TCP connections opened by `root_pid`
/// and its child processes. Invokes `on_endpoint` once for each newly observed remote `ip:port`.
pub fn spawn_socket_watcher<F>(
    root_pid: u32,
    stop: Arc<AtomicBool>,
    mut on_endpoint: F,
) -> JoinHandle<()>
where
    F: FnMut(String) + Send + 'static,
{
    thread::spawn(move || {
        let mut seen: HashSet<String> = HashSet::new();
        while !stop.load(Ordering::Relaxed) {
            for endpoint in list_tree_remote_endpoints(root_pid) {
                if seen.insert(endpoint.clone()) {
                    on_endpoint(endpoint);
                }
            }
            // Sleep in short slices so child exit joins promptly
            for _ in 0..8 {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
    })
}

#[cfg(target_os = "linux")]
fn list_tree_remote_endpoints(root_pid: u32) -> Vec<String> {
    use std::collections::HashMap;
    use std::fs;
    use std::net::{Ipv4Addr, Ipv6Addr};

    let pids = collect_linux_descendants(root_pid);
    let mut socket_inodes: HashSet<u64> = HashSet::new();

    for pid in pids {
        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(entries) = fs::read_dir(fd_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(link) = fs::read_link(entry.path()) else {
                continue;
            };
            let s = link.to_string_lossy();
            if let Some(rest) = s.strip_prefix("socket:[") {
                if let Some(num_str) = rest.strip_suffix(']') {
                    if let Ok(inode) = num_str.parse::<u64>() {
                        socket_inodes.insert(inode);
                    }
                }
            }
        }
    }

    if socket_inodes.is_empty() {
        return Vec::new();
    }

    let mut inode_to_remote: HashMap<u64, String> = HashMap::new();

    // Parse /proc/net/tcp (IPv4)
    if let Ok(tcp4) = fs::read_to_string("/proc/net/tcp") {
        for line in tcp4.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            let state = cols[3];
            // 01 = ESTABLISHED, 02 = SYN_SENT
            if state != "01" && state != "02" {
                continue;
            }
            let Ok(inode) = cols[9].parse::<u64>() else {
                continue;
            };
            if !socket_inodes.contains(&inode) {
                continue;
            }
            if let Some((ip_hex, port_hex)) = cols[2].split_once(':') {
                if let (Ok(raw_ip), Ok(port)) = (
                    u32::from_str_radix(ip_hex, 16),
                    u16::from_str_radix(port_hex, 16),
                ) {
                    let ip = Ipv4Addr::from(raw_ip.to_be());
                    if !ip.is_loopback() && !ip.is_unspecified() && port > 0 {
                        inode_to_remote.insert(inode, format!("{ip}:{port}"));
                    }
                }
            }
        }
    }

    // Parse /proc/net/tcp6 (IPv6)
    if let Ok(tcp6) = fs::read_to_string("/proc/net/tcp6") {
        for line in tcp6.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            let state = cols[3];
            if state != "01" && state != "02" {
                continue;
            }
            let Ok(inode) = cols[9].parse::<u64>() else {
                continue;
            };
            if !socket_inodes.contains(&inode) {
                continue;
            }
            if let Some((ip_hex, port_hex)) = cols[2].split_once(':') {
                if ip_hex.len() == 32 {
                    if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                        let mut octets = [0u8; 16];
                        let mut ok = true;
                        for word_idx in 0..4 {
                            let slice = &ip_hex[word_idx * 8..(word_idx + 1) * 8];
                            match u32::from_str_radix(slice, 16) {
                                Ok(w) => {
                                    let bytes = w.to_ne_bytes();
                                    octets[word_idx * 4..word_idx * 4 + 4].copy_from_slice(&bytes);
                                }
                                Err(_) => {
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        if ok {
                            let ip6 = Ipv6Addr::from(octets);
                            if !ip6.is_loopback() && !ip6.is_unspecified() && port > 0 {
                                let rendered = match ip6.to_ipv4_mapped() {
                                    Some(v4) if !v4.is_loopback() => format!("{v4}:{port}"),
                                    Some(_) => continue,
                                    None => format!("[{ip6}]:{port}"),
                                };
                                inode_to_remote.insert(inode, rendered);
                            }
                        }
                    }
                }
            }
        }
    }

    let mut out: Vec<String> = inode_to_remote.into_values().collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(target_os = "linux")]
fn collect_linux_descendants(root_pid: u32) -> Vec<u32> {
    use std::collections::HashMap;
    use std::fs;

    let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            let stat_path = format!("/proc/{pid}/stat");
            let Ok(stat_raw) = fs::read_to_string(stat_path) else {
                continue;
            };
            // `/proc/<pid>/stat` format: `pid (comm) state ppid ...`
            if let Some(after_comm) = stat_raw.rfind(") ") {
                let fields: Vec<&str> = stat_raw[after_comm + 2..].split_whitespace().collect();
                if fields.len() >= 2 {
                    if let Ok(ppid) = fields[1].parse::<u32>() {
                        children_map.entry(ppid).or_default().push(pid);
                    }
                }
            }
        }
    }

    let mut result = vec![root_pid];
    let mut idx = 0usize;
    while idx < result.len() {
        let cur = result[idx];
        idx += 1;
        if let Some(kids) = children_map.get(&cur) {
            for &k in kids {
                if !result.contains(&k) {
                    result.push(k);
                }
            }
        }
    }
    result
}

#[cfg(target_os = "macos")]
fn list_tree_remote_endpoints(root_pid: u32) -> Vec<String> {
    use std::process::Command;

    let mut pids = vec![root_pid];
    let mut idx = 0usize;
    while idx < pids.len() {
        let cur = pids[idx];
        idx += 1;
        if let Ok(out) = Command::new("pgrep")
            .args(["-P", &cur.to_string()])
            .output()
        {
            if out.status.success() {
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    if let Ok(child) = line.trim().parse::<u32>() {
                        if !pids.contains(&child) {
                            pids.push(child);
                        }
                    }
                }
            }
        }
    }

    let pid_csv = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let Ok(out) = Command::new("lsof")
        .args([
            "-nP",
            "-iTCP",
            "-sTCP:ESTABLISHED,SYN_SENT",
            "-a",
            "-p",
            &pid_csv,
            "-Fn",
        ])
        .output()
    else {
        return Vec::new();
    };

    let mut remotes = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // lsof -Fn network line: `n192.168.1.5:54122->104.18.12.34:443`
        if let Some(net) = line.strip_prefix('n') {
            if let Some((_, remote)) = net.split_once("->") {
                if !remote.starts_with("127.0.0.1:") && !remote.starts_with("[::1]:") {
                    remotes.push(remote.to_string());
                }
            }
        }
    }
    remotes.sort();
    remotes.dedup();
    remotes
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn list_tree_remote_endpoints(_root_pid: u32) -> Vec<String> {
    Vec::new()
}
