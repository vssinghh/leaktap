use std::collections::HashSet;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct SocketObservation {
    pub proto: &'static str,
    pub remote: String,
    pub is_proxy_loopback: bool,
    pub pid: u32,
    pub comm: String,
    pub cmdline: String,
}

/// Whether per-process OS socket telemetry is implemented on the current platform.
pub const OS_SOCKET_WATCH_SUPPORTED: bool = cfg!(any(target_os = "linux", target_os = "macos"));

/// Marks the current `leaktap` process non-dumpable (`PR_SET_DUMPABLE = 0`) on Linux so
/// `/proc/<leaktap_pid>/environ` and `/proc/<leaktap_pid>/mem` become `0400 root:root` and
/// cannot be read by scrubbed same-UID child processes via `/proc/$PPID/environ`.
/// Note: `execve(2)` automatically resets `dumpable` to `1` for spawned child processes.
pub fn disable_process_dumpable() {
    #[cfg(target_os = "linux")]
    unsafe {
        let _ = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// Marks the current `leaktap` process as a Linux child subreaper (`PR_SET_CHILD_SUBREAPER`)
/// so double-forked background processes (`(curl ... &)`) reparent to `leaktap` instead of `PID 1`.
pub fn enable_child_subreaper() {
    #[cfg(target_os = "linux")]
    unsafe {
        let _ = libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    }
}

/// Reaps any reparented zombie grandchildren on Linux without blocking (post-exit cleanup).
pub fn reap_reparented_zombies() {
    #[cfg(target_os = "linux")]
    unsafe {
        let mut status: libc::c_int = 0;
        while libc::waitpid(-1, &mut status, libc::WNOHANG) > 0 {}
    }
}

/// Reaps reparented zombie grandchildren (`ppid == leaktap_pid`, state `Z`) during an active
/// session while strictly skipping `exclude_pid` so `child.try_wait()` retains the direct child's exit code.
pub fn reap_reparented_zombies_except(exclude_pid: u32) {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = exclude_pid;
    }
    #[cfg(target_os = "linux")]
    {
        let my_pid = std::process::id();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return;
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            if pid == exclude_pid || pid == my_pid {
                continue;
            }
            let Ok(stat_raw) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            let Some(after_comm) = stat_raw.rfind(") ") else {
                continue;
            };
            let mut fields = stat_raw[after_comm + 2..].split_whitespace();
            let Some(state) = fields.next() else {
                continue;
            };
            let Some(ppid_str) = fields.next() else {
                continue;
            };
            if state == "Z" && ppid_str.parse::<u32>().ok() == Some(my_pid) {
                unsafe {
                    let mut status: libc::c_int = 0;
                    let _ = libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG);
                }
            }
        }
    }
}

/// Spawns a zero-root background poller watching outbound TCP and connected UDP sockets opened by
/// `root_pid` and its descendants (including reparented orphans).
pub fn spawn_socket_watcher<F>(
    root_pid: u32,
    ignore_loopback_port: Option<u16>,
    stop: Arc<AtomicBool>,
    mut on_socket: F,
) -> JoinHandle<()>
where
    F: FnMut(SocketObservation) + Send + 'static,
{
    let supervisor_pid = std::process::id();
    let proxy_ports = detect_local_proxy_ports();

    thread::spawn(move || {
        if !OS_SOCKET_WATCH_SUPPORTED {
            return;
        }
        #[cfg(target_os = "macos")]
        let poll_interval = Duration::from_millis(250);
        #[cfg(not(target_os = "macos"))]
        let poll_interval = Duration::from_millis(20);

        #[cfg(target_os = "macos")]
        let mut mac_cmdline_cache: std::collections::HashMap<u32, String> =
            std::collections::HashMap::new();

        let mut seen: HashSet<(String, String, String)> = HashSet::new();
        #[allow(unused_mut)]
        let mut sweep = |seen: &mut HashSet<(String, String, String)>, on_socket: &mut F| {
            for mut obs in
                list_tree_sockets(supervisor_pid, root_pid, ignore_loopback_port, &proxy_ports)
            {
                let dedup_key = (obs.proto.to_string(), obs.remote.clone(), obs.comm.clone());
                if seen.insert(dedup_key) {
                    #[cfg(target_os = "macos")]
                    if obs.cmdline.is_empty() {
                        obs.cmdline = mac_cmdline_cache
                            .entry(obs.pid)
                            .or_insert_with(|| resolve_macos_pid_cmdline(obs.pid))
                            .clone();
                    }
                    let _ = &mut obs;
                    on_socket(obs);
                }
            }
        };

        loop {
            sweep(&mut seen, &mut on_socket);
            if stop.load(Ordering::Relaxed) {
                // Brief post-exit grace sweep for double-forked background children finishing TCP/UDP handshakes
                thread::sleep(Duration::from_millis(25));
                sweep(&mut seen, &mut on_socket);
                break;
            }
            thread::sleep(poll_interval);
        }
    })
}

#[cfg(target_os = "macos")]
fn resolve_macos_pid_cmdline(pid: u32) -> String {
    std::process::Command::new("ps")
        .args(["-o", "args=", "-p", &pid.to_string()])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn detect_local_proxy_ports() -> HashSet<u16> {
    let mut ports = HashSet::new();
    for var in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        let Ok(val) = env::var(var) else {
            continue;
        };
        let lower = val.trim().to_ascii_lowercase();
        let after_scheme = lower
            .split_once("://")
            .map_or(lower.as_str(), |(_, rest)| rest);
        let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
        let host_port = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
        let is_local = host_port.starts_with("127.0.0.1:")
            || host_port.starts_with("localhost:")
            || host_port.starts_with("[::1]:");
        if is_local {
            if let Some((_, p_str)) = host_port.rsplit_once(':') {
                if let Ok(p) = p_str.parse::<u16>() {
                    ports.insert(p);
                }
            }
        }
    }
    ports
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct ProcOwner {
    pid: u32,
    comm: String,
    cmdline: String,
}

#[cfg(target_os = "linux")]
fn list_tree_sockets(
    supervisor_pid: u32,
    root_pid: u32,
    ignore_loopback_port: Option<u16>,
    proxy_ports: &HashSet<u16>,
) -> Vec<SocketObservation> {
    use std::collections::HashMap;
    use std::fs;
    use std::net::{Ipv4Addr, Ipv6Addr};

    let pids = collect_linux_descendants(supervisor_pid, root_pid);
    if pids.is_empty() {
        return Vec::new();
    }

    let mut inode_owner: HashMap<u64, ProcOwner> = HashMap::new();

    for pid in pids {
        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(entries) = fs::read_dir(fd_dir) else {
            continue;
        };
        let mut proc_info: Option<ProcOwner> = None;

        for entry in entries.flatten() {
            let Ok(link) = fs::read_link(entry.path()) else {
                continue;
            };
            let s = link.to_string_lossy();
            if let Some(rest) = s.strip_prefix("socket:[") {
                if let Some(num_str) = rest.strip_suffix(']') {
                    if let Ok(inode) = num_str.parse::<u64>() {
                        let owner = proc_info
                            .get_or_insert_with(|| read_linux_proc_owner(pid))
                            .clone();
                        inode_owner.entry(inode).or_insert(owner);
                    }
                }
            }
        }
    }

    if inode_owner.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();

    let mut check_v4_table = |path: &str, proto: &'static str, allow_udp_states: bool| {
        let Ok(content) = fs::read_to_string(path) else {
            return;
        };
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            let state = cols[3];
            // TCP: 01 = ESTABLISHED, 02 = SYN_SENT, 06 = TIME_WAIT (skip), 08 = CLOSE_WAIT
            // UDP connected sockets use 01 (established) or 07 with non-zero rem_address
            let active = if allow_udp_states {
                state == "01" || state == "07"
            } else {
                state == "01" || state == "02" || state == "08"
            };
            if !active {
                continue;
            }
            let Ok(inode) = cols[9].parse::<u64>() else {
                continue;
            };
            let Some(owner) = inode_owner.get(&inode) else {
                continue;
            };
            let Some((ip_hex, port_hex)) = cols[2].split_once(':') else {
                continue;
            };
            let (Ok(raw_ip), Ok(port)) = (
                u32::from_str_radix(ip_hex, 16),
                u16::from_str_radix(port_hex, 16),
            ) else {
                continue;
            };
            if port == 0 {
                continue;
            }
            let ip = Ipv4Addr::from(raw_ip.to_be());
            if ip.is_unspecified() {
                continue;
            }
            let is_loopback = ip.is_loopback();
            if is_loopback && (ignore_loopback_port == Some(port) || port == 53) {
                continue;
            }
            out.push(SocketObservation {
                proto,
                remote: format!("{ip}:{port}"),
                is_proxy_loopback: is_loopback && proxy_ports.contains(&port),
                pid: owner.pid,
                comm: owner.comm.clone(),
                cmdline: owner.cmdline.clone(),
            });
        }
    };

    check_v4_table("/proc/net/tcp", "TCP", false);
    check_v4_table("/proc/net/udp", "UDP", true);

    let mut check_v6_table = |path: &str, proto: &'static str, allow_udp_states: bool| {
        let Ok(content) = fs::read_to_string(path) else {
            return;
        };
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            let state = cols[3];
            let active = if allow_udp_states {
                state == "01" || state == "07"
            } else {
                state == "01" || state == "02" || state == "08"
            };
            if !active {
                continue;
            }
            let Ok(inode) = cols[9].parse::<u64>() else {
                continue;
            };
            let Some(owner) = inode_owner.get(&inode) else {
                continue;
            };
            let Some((ip_hex, port_hex)) = cols[2].split_once(':') else {
                continue;
            };
            if ip_hex.len() != 32 {
                continue;
            }
            let Ok(port) = u16::from_str_radix(port_hex, 16) else {
                continue;
            };
            if port == 0 {
                continue;
            }
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
            if !ok {
                continue;
            }
            let ip6 = Ipv6Addr::from(octets);
            if ip6.is_unspecified() {
                continue;
            }
            let (rendered, is_loopback) = match ip6.to_ipv4_mapped() {
                Some(v4) => (format!("{v4}:{port}"), v4.is_loopback()),
                None => (format!("[{ip6}]:{port}"), ip6.is_loopback()),
            };
            if is_loopback && (ignore_loopback_port == Some(port) || port == 53) {
                continue;
            }
            out.push(SocketObservation {
                proto,
                remote: rendered,
                is_proxy_loopback: is_loopback && proxy_ports.contains(&port),
                pid: owner.pid,
                comm: owner.comm.clone(),
                cmdline: owner.cmdline.clone(),
            });
        }
    };

    check_v6_table("/proc/net/tcp6", "TCP", false);
    check_v6_table("/proc/net/udp6", "UDP", true);

    out
}

#[cfg(target_os = "linux")]
fn read_linux_proc_owner(pid: u32) -> ProcOwner {
    use std::fs;
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "process".to_string());

    let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .map(|bytes| {
            bytes
                .split(|&b| b == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();

    ProcOwner { pid, comm, cmdline }
}

#[cfg(target_os = "linux")]
fn collect_linux_descendants(supervisor_pid: u32, root_pid: u32) -> Vec<u32> {
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
    // Include any double-forked orphans reparented to `leaktap` (`supervisor_pid`) via PR_SET_CHILD_SUBREAPER,
    // without including `supervisor_pid` itself.
    if let Some(reparented) = children_map.get(&supervisor_pid) {
        for &child in reparented {
            if !result.contains(&child) {
                result.push(child);
            }
        }
    }

    let mut idx = 0usize;
    while idx < result.len() {
        let cur = result[idx];
        idx += 1;
        if let Some(kids) = children_map.get(&cur) {
            for &k in kids {
                if k != supervisor_pid && !result.contains(&k) {
                    result.push(k);
                }
            }
        }
    }
    result
}

#[cfg(target_os = "macos")]
fn collect_macos_descendants(root_pid: u32) -> Vec<u32> {
    use std::collections::HashMap;
    use std::process::Command;

    let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
    if let Ok(out) = Command::new("ps")
        .args(["-ax", "-o", "pid=,ppid="])
        .output()
    {
        if out.status.success() {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let mut parts = line.split_whitespace();
                let (Some(pid_s), Some(ppid_s)) = (parts.next(), parts.next()) else {
                    continue;
                };
                if let (Ok(pid), Ok(ppid)) = (pid_s.parse::<u32>(), ppid_s.parse::<u32>()) {
                    children_map.entry(ppid).or_default().push(pid);
                }
            }
        }
    }

    let mut pids = vec![root_pid];
    let mut idx = 0usize;
    while idx < pids.len() {
        let cur = pids[idx];
        idx += 1;
        if let Some(kids) = children_map.get(&cur) {
            for &child in kids {
                if !pids.contains(&child) {
                    pids.push(child);
                }
            }
        }
    }
    pids
}

#[cfg(target_os = "macos")]
fn list_tree_sockets(
    _supervisor_pid: u32,
    root_pid: u32,
    ignore_loopback_port: Option<u16>,
    proxy_ports: &HashSet<u16>,
) -> Vec<SocketObservation> {
    use std::process::Command;

    let pids = collect_macos_descendants(root_pid);

    let pid_csv = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let Ok(out) = Command::new("lsof")
        .args(["-nP", "-iTCP", "-iUDP", "-a", "-p", &pid_csv, "-FpcPn"])
        .output()
    else {
        return Vec::new();
    };

    let mut observations = Vec::new();
    let mut cur_pid = root_pid;
    let mut cur_comm = String::from("process");
    let mut cur_proto: &'static str = "TCP";

    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(p_str) = line.strip_prefix('p') {
            cur_pid = p_str.parse::<u32>().unwrap_or(root_pid);
        } else if let Some(c_str) = line.strip_prefix('c') {
            cur_comm = c_str.to_string();
        } else if let Some(proto_str) = line.strip_prefix('P') {
            cur_proto = if proto_str.eq_ignore_ascii_case("UDP") {
                "UDP"
            } else {
                "TCP"
            };
        } else if let Some(net) = line.strip_prefix('n') {
            if let Some((_, remote)) = net.split_once("->") {
                let is_loopback = remote.starts_with("127.0.0.1:") || remote.starts_with("[::1]:");
                let port = remote
                    .rsplit_once(':')
                    .and_then(|(_, p)| p.parse::<u16>().ok());
                if is_loopback && (port == ignore_loopback_port || port == Some(53)) {
                    continue;
                }
                observations.push(SocketObservation {
                    proto: cur_proto,
                    remote: remote.to_string(),
                    is_proxy_loopback: is_loopback
                        && port.is_some_and(|p| proxy_ports.contains(&p)),
                    pid: cur_pid,
                    comm: cur_comm.clone(),
                    cmdline: String::new(),
                });
            }
        }
    }
    observations
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn list_tree_sockets(
    _supervisor_pid: u32,
    _root_pid: u32,
    _ignore_loopback_port: Option<u16>,
    _proxy_ports: &HashSet<u16>,
) -> Vec<SocketObservation> {
    Vec::new()
}
