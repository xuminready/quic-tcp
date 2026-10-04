use crate::quic_to_tcp::{ServerMode, run_quic_to_tcp};
use crate::tcp_to_quic::{ClientMode, run_tcp_to_quic};
use crate::{normalize_socket_addr, request_shutdown};
use log::{Level, LevelFilter, Log, Metadata, Record, error, info};
use std::collections::VecDeque;
use std::ffi::{CStr, CString, c_char, c_void};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_LOG_LINES: usize = 4000;

static LOG_BUFFER: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
static LOGGER_INIT: OnceLock<()> = OnceLock::new();
static QUIC_TO_TCP_RUNNING: AtomicBool = AtomicBool::new(false);
static TCP_TO_QUIC_RUNNING: AtomicBool = AtomicBool::new(false);
// 1 = Error, 2 = Warn, 3 = Info, 4 = Debug, 5 = Trace
static CURRENT_LOG_LEVEL: AtomicUsize = AtomicUsize::new(3);

struct ProxyLogger;

static PROXY_LOGGER: ProxyLogger = ProxyLogger;

fn get_log_buffer() -> &'static Mutex<VecDeque<String>> {
    LOG_BUFFER.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_LOG_LINES)))
}

fn level_from_usize(v: usize) -> Level {
    match v {
        1 => Level::Error,
        2 => Level::Warn,
        3 => Level::Info,
        4 => Level::Debug,
        _ => Level::Trace,
    }
}

fn parse_level_filter(raw: &str) -> (usize, LevelFilter, &'static str) {
    let lower = raw.trim().to_ascii_lowercase();
    if lower.contains("trace") {
        (5, LevelFilter::Trace, "trace")
    } else if lower.contains("debug") {
        (4, LevelFilter::Debug, "debug")
    } else if lower.contains("warn") {
        (2, LevelFilter::Warn, "warn")
    } else if lower.contains("error") {
        (1, LevelFilter::Error, "error")
    } else {
        (3, LevelFilter::Info, "info")
    }
}

pub fn set_proxy_log_level(level_str: &str) {
    init_proxy_logger();
    let (code, filter, canonical) = parse_level_filter(level_str);
    let prev = CURRENT_LOG_LEVEL.swap(code, Ordering::SeqCst);
    log::set_max_level(filter);
    if prev != code {
        push_log_line(
            "INFO",
            &format!("RUST_LOG level set to '{}'", canonical.to_uppercase()),
        );
    }
}

fn format_timestamp() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = dur.as_secs();
    let hours = (total_secs / 3600) % 24;
    let mins = (total_secs / 60) % 60;
    let secs = total_secs % 60;
    let millis = dur.subsec_millis();
    format!("{hours:02}:{mins:02}:{secs:02}.{millis:03}")
}

pub fn push_log_line(level: &str, msg: &str) {
    let line = format!("[{}] [{}] {}", format_timestamp(), level, msg);
    if let Ok(mut guard) = get_log_buffer().lock() {
        if guard.len() >= MAX_LOG_LINES {
            guard.pop_front();
        }
        guard.push_back(line);
    }

    #[cfg(target_os = "android")]
    {
        #[link(name = "log")]
        unsafe extern "C" {
            fn __android_log_write(prio: i32, tag: *const c_char, text: *const c_char) -> i32;
        }
        let prio = match level {
            "ERROR" => 6,
            "WARN" => 5,
            "INFO" => 4,
            "DEBUG" => 3,
            _ => 2,
        };
        if let (Ok(tag), Ok(text)) = (
            CString::new("QuicTcp"),
            CString::new(msg.replace('\0', " ")),
        ) {
            unsafe {
                __android_log_write(prio, tag.as_ptr(), text.as_ptr());
            }
        }
    }
}

impl Log for ProxyLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        let max_lvl = level_from_usize(CURRENT_LOG_LEVEL.load(Ordering::Relaxed));
        metadata.level() <= max_lvl
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let msg = format!("{}", record.args());
            push_log_line(record.level().as_str(), &msg);
        }
    }

    fn flush(&self) {}
}

pub fn init_proxy_logger() {
    LOGGER_INIT.get_or_init(|| {
        let _ = log::set_logger(&PROXY_LOGGER);
        let (_, filter, _) = match CURRENT_LOG_LEVEL.load(Ordering::Relaxed) {
            1 => (1, LevelFilter::Error, "error"),
            2 => (2, LevelFilter::Warn, "warn"),
            4 => (4, LevelFilter::Debug, "debug"),
            5 => (5, LevelFilter::Trace, "trace"),
            _ => (3, LevelFilter::Info, "info"),
        };
        log::set_max_level(filter);
    });
}

pub fn drain_log_lines() -> String {
    init_proxy_logger();
    let Ok(mut guard) = get_log_buffer().lock() else {
        return String::new();
    };
    if guard.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    while let Some(line) = guard.pop_front() {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&line);
    }
    out
}

fn parse_socket_addr(input: &str, label: &str) -> Result<SocketAddr, String> {
    let trimmed = input.trim();
    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return Ok(normalize_socket_addr(addr));
    }
    if let Ok(mut iter) = trimmed.to_socket_addrs() {
        if let Some(addr) = iter.next() {
            return Ok(normalize_socket_addr(addr));
        }
    }
    Err(format!("Invalid {} address '{}'", label, trimmed))
}

fn wait_for_previous_stop(running_flag: &AtomicBool) {
    if running_flag.load(Ordering::SeqCst) {
        request_shutdown();
        for _ in 0..60 {
            if !running_flag.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

// ============================================================================
// Raw JNI Bindings (Compatible with both 32-bit armeabi-v7a and 64-bit arm64-v8a)
// ============================================================================

pub type JNIEnv = *const *const usize;
pub type JClass = *const c_void;
pub type JString = *const c_void;
pub type JBoolean = u8;

type NewStringUTF = unsafe extern "system" fn(JNIEnv, *const c_char) -> JString;
type GetStringUTFChars = unsafe extern "system" fn(JNIEnv, JString, *mut JBoolean) -> *const c_char;
type ReleaseStringUTFChars = unsafe extern "system" fn(JNIEnv, JString, *const c_char);

unsafe fn jstring_to_string(env: JNIEnv, s: JString) -> String {
    if env.is_null() || s.is_null() {
        return String::new();
    }
    unsafe {
        let table = *env;
        let get_fn: GetStringUTFChars = std::mem::transmute(*table.add(169));
        let rel_fn: ReleaseStringUTFChars = std::mem::transmute(*table.add(170));
        let ptr = get_fn(env, s, std::ptr::null_mut());
        if ptr.is_null() {
            return String::new();
        }
        let res = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        rel_fn(env, s, ptr);
        res
    }
}

unsafe fn string_to_jstring(env: JNIEnv, s: &str) -> JString {
    if env.is_null() {
        return std::ptr::null();
    }
    let sanitized = s.replace('\0', "");
    let Ok(cstr) = CString::new(sanitized) else {
        return std::ptr::null();
    };
    unsafe {
        let table = *env;
        let new_fn: NewStringUTF = std::mem::transmute(*table.add(167));
        new_fn(env, cstr.as_ptr())
    }
}

// ----------------------------------------------------------------------------
// QuicToTcpLib JNI Exports (for libquic_to_tcp.so)
// ----------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_quictcp_app_QuicToTcpLib_start(
    env: JNIEnv,
    _class: JClass,
    is_p2p: JBoolean,
    rendezvous_or_udp_addr: JString,
    target_tcp_addr: JString,
    secret: JString,
) -> JBoolean {
    init_proxy_logger();
    wait_for_previous_stop(&QUIC_TO_TCP_RUNNING);

    let rdv_or_udp = unsafe { jstring_to_string(env, rendezvous_or_udp_addr) };
    let tcp_target = unsafe { jstring_to_string(env, target_tcp_addr) };
    let secret_code = {
        let s = crate::auth::normalize_secret(&unsafe { jstring_to_string(env, secret) });
        if s.is_empty() {
            "tunnel-ssh-secret".to_string()
        } else {
            s
        }
    };
    let tunnel_id = crate::auth::derive_tunnel_id(&secret_code);
    info!(
        "[quic-to-tcp] Using Secret: \"{}\" (Tunnel ID: {})",
        secret_code, tunnel_id
    );

    let remote_tcp_addr = match parse_socket_addr(&tcp_target, "Target TCP") {
        Ok(a) => a,
        Err(e) => {
            error!("[quic-to-tcp] {}", e);
            return 0;
        }
    };

    let mode = if is_p2p != 0 {
        let rendezvous_addr = match parse_socket_addr(&rdv_or_udp, "Rendezvous") {
            Ok(a) => a,
            Err(e) => {
                error!("[quic-to-tcp] {}", e);
                return 0;
            }
        };
        ServerMode::P2p {
            rendezvous_addr,
            remote_tcp_addr,
            tunnel_code: secret_code,
        }
    } else {
        let udp_str = if rdv_or_udp.trim().is_empty() {
            "0.0.0.0:4433"
        } else {
            rdv_or_udp.trim()
        };
        let local_udp_addr = match parse_socket_addr(udp_str, "Local UDP") {
            Ok(a) => a,
            Err(e) => {
                error!("[quic-to-tcp] {}", e);
                return 0;
            }
        };
        ServerMode::Direct {
            local_udp_addr,
            remote_tcp_addr,
            tunnel_code: secret_code,
        }
    };

    QUIC_TO_TCP_RUNNING.store(true, Ordering::SeqCst);
    std::thread::spawn(move || {
        info!("Starting quic-to-tcp background worker...");
        if let Err(e) = run_quic_to_tcp(mode) {
            if e.to_string() != "Shutdown requested" {
                error!("[quic-to-tcp] Exited with error: {}", e);
            } else {
                info!("[quic-to-tcp] Stopped by user.");
            }
        }
        QUIC_TO_TCP_RUNNING.store(false, Ordering::SeqCst);
    });

    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_quictcp_app_QuicToTcpLib_stop(_env: JNIEnv, _class: JClass) {
    init_proxy_logger();
    info!("Stopping quic-to-tcp...");
    request_shutdown();
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_quictcp_app_QuicToTcpLib_isRunning(
    _env: JNIEnv,
    _class: JClass,
) -> JBoolean {
    u8::from(QUIC_TO_TCP_RUNNING.load(Ordering::SeqCst))
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_quictcp_app_QuicToTcpLib_drainLogs(
    env: JNIEnv,
    _class: JClass,
) -> JString {
    let logs = drain_log_lines();
    unsafe { string_to_jstring(env, &logs) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_quictcp_app_QuicToTcpLib_setLogLevel(
    env: JNIEnv,
    _class: JClass,
    level: JString,
) {
    let lvl = unsafe { jstring_to_string(env, level) };
    set_proxy_log_level(&lvl);
}

// ----------------------------------------------------------------------------
// TcpToQuicLib JNI Exports (for libtcp_to_quic.so)
// ----------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_quictcp_app_TcpToQuicLib_start(
    env: JNIEnv,
    _class: JClass,
    is_p2p: JBoolean,
    rendezvous_or_udp_addr: JString,
    local_tcp_addr_str: JString,
    secret: JString,
) -> JBoolean {
    init_proxy_logger();
    wait_for_previous_stop(&TCP_TO_QUIC_RUNNING);

    let rdv_or_udp = unsafe { jstring_to_string(env, rendezvous_or_udp_addr) };
    let tcp_local = unsafe { jstring_to_string(env, local_tcp_addr_str) };
    let secret_code = {
        let s = crate::auth::normalize_secret(&unsafe { jstring_to_string(env, secret) });
        if s.is_empty() {
            "tunnel-ssh-secret".to_string()
        } else {
            s
        }
    };
    let tunnel_id = crate::auth::derive_tunnel_id(&secret_code);
    info!(
        "[tcp-to-quic] Using Secret: \"{}\" (Tunnel ID: {})",
        secret_code, tunnel_id
    );

    let local_tcp_addr = match parse_socket_addr(&tcp_local, "Local TCP") {
        Ok(a) => a,
        Err(e) => {
            error!("[tcp-to-quic] {}", e);
            return 0;
        }
    };

    let mode = if is_p2p != 0 {
        let rendezvous_addr = match parse_socket_addr(&rdv_or_udp, "Rendezvous") {
            Ok(a) => a,
            Err(e) => {
                error!("[tcp-to-quic] {}", e);
                return 0;
            }
        };
        ClientMode::P2p {
            rendezvous_addr,
            local_tcp_addr,
            tunnel_code: secret_code,
        }
    } else {
        let remote_udp_addr = match parse_socket_addr(&rdv_or_udp, "Remote QUIC UDP") {
            Ok(a) => a,
            Err(e) => {
                error!("[tcp-to-quic] {}", e);
                return 0;
            }
        };
        ClientMode::Direct {
            local_tcp_addr,
            remote_udp_addr,
            tunnel_code: secret_code,
        }
    };

    TCP_TO_QUIC_RUNNING.store(true, Ordering::SeqCst);
    std::thread::spawn(move || {
        info!("Starting tcp-to-quic background worker...");
        if let Err(e) = run_tcp_to_quic(mode) {
            if e.to_string() != "Shutdown requested" {
                error!("[tcp-to-quic] Exited with error: {}", e);
            } else {
                info!("[tcp-to-quic] Stopped by user.");
            }
        }
        TCP_TO_QUIC_RUNNING.store(false, Ordering::SeqCst);
    });

    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_quictcp_app_TcpToQuicLib_stop(_env: JNIEnv, _class: JClass) {
    init_proxy_logger();
    info!("Stopping tcp-to-quic (releasing server if connected)...");
    request_shutdown();
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_quictcp_app_TcpToQuicLib_isRunning(
    _env: JNIEnv,
    _class: JClass,
) -> JBoolean {
    u8::from(TCP_TO_QUIC_RUNNING.load(Ordering::SeqCst))
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_quictcp_app_TcpToQuicLib_drainLogs(
    env: JNIEnv,
    _class: JClass,
) -> JString {
    let logs = drain_log_lines();
    unsafe { string_to_jstring(env, &logs) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_quictcp_app_TcpToQuicLib_setLogLevel(
    env: JNIEnv,
    _class: JClass,
    level: JString,
) {
    let lvl = unsafe { jstring_to_string(env, level) };
    set_proxy_log_level(&lvl);
}
