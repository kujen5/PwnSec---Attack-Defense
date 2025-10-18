#!/usr/bin/env python3
import argparse, os, sys, re, shutil
from pathlib import Path
from string import Template

# markers / filenames
MARK_PHP = "/* wl:php */"
GO_STUB_NAME = "zz_ip_whitelist.go"
RS_STUB_NAME = "ip_whitelist.rs"

# ---------- PHP guard snippet ----------
PHP_SNIPPET_TEMPLATE = """<?php {MARK}
$__WL = {ALLOW_LIST};
$__LOG = {LOG_PATH_PHP};

function __wl_ip() {{
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? ($_SERVER['REMOTE_ADDR'] ?? '');
    if (strpos($ip, ',') !== false) {{ $ip = trim(explode(',', $ip)[0]); }}
    return $ip;
}}
function __wl_block($ip) {{
    $line = date('c')." BLOCK ".$ip." ".($_SERVER['REQUEST_METHOD']??'')." ".($_SERVER['REQUEST_URI']??'')."\\n";
    if ($__LOG && @file_put_contents($__LOG, $line, FILE_APPEND) === false) {{ error_log($line); }}
    http_response_code(403);
    exit('Forbidden');
}}
function __wl_cidr_match($ip, $cidr) {{
    if (strpos($cidr, '/') === false) return $ip === $cidr;
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) return false;
    list($sub, $mask) = explode('/', $cidr, 2);
    $mask = (int)$mask;
    $ipL  = ip2long($ip);
    $subL = ip2long($sub);
    $maskL = -1 << (32 - $mask);
    return ($ipL & $maskL) === ($subL & $maskL);
}}
$__ip = __wl_ip();
$__ok = false;
foreach ($__WL as $c) {{ if (__wl_cidr_match($__ip, $c)) {{ $__ok = true; break; }} }}
if (!$__ok) {{ __wl_block($__ip); }}
?>"""

# ---------- Go stub (net/http wrapper) ----------
GO_STUB_TEMPLATE = Template(r'''package main

import (
	"log"
	"net"
	"net/http"
	"strings"
)

var wlCIDRs = []string{$allow_list_go}
var wlNets = parseCIDRs(wlCIDRs)

func Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !allowed(ip) {
			log.Printf("BLOCK %s %s %s", ip, r.Method, r.URL.Path)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		parts := strings.Split(xf, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil { return r.RemoteAddr }
	return host
}

func parseCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, ipnet, err := net.ParseCIDR(c); err == nil {
			out = append(out, ipnet)
		} else {
			if ip := net.ParseIP(c); ip != nil {
				mask := net.CIDRMask(128, 128)
				if ip.To4() != nil { mask = net.CIDRMask(32, 32) }
				out = append(out, &net.IPNet{IP: ip, Mask: mask})
			}
		}
	}
	return out
}

func allowed(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		host, _, err := net.SplitHostPort(ipStr)
		if err == nil { ip = net.ParseIP(host) }
	}
	if ip == nil { return false }
	for _, n := range wlNets {
		if n.Contains(ip) { return true }
	}
	return false
}
''')

# ---------- Rust stub (actix middleware) ----------
RS_STUB_TEMPLATE = Template(r'''use std::str::FromStr;
use once_cell::sync::Lazy;
use std::sync::Arc;

static ALLOW: Lazy<Arc<Vec<String>>> = Lazy::new(|| Arc::new(vec![$allow_list_rs]));

fn first_hop(xff: Option<&str>) -> Option<String> {
    if let Some(v) = xff {
        if let Some(first) = v.split(',').next() {
            return Some(first.trim().to_string());
        }
    }
    None
}

pub fn allowed(ip: &str) -> bool {
    if ALLOW.iter().any(|a| a == ip) { return true; }
    if let Ok(ipv4) = std::net::Ipv4Addr::from_str(ip) {
        for a in ALLOW.iter() {
            if let Some((sub, mask)) = a.split_once('/') {
                if let (Ok(s), Ok(m)) = (std::net::Ipv4Addr::from_str(sub), mask.parse::<u32>()) {
                    let m = (!0u32) << (32 - m);
                    if (u32::from(ipv4) & m) == (u32::from(s) & m) { return true; }
                }
            }
        }
    }
    false
}

pub fn deny_unless_allowed(_method: &str, path: &str, peer_ip: &str, xff: Option<&str>) -> Result<(), (u16, &'static str)> {
    let ip = first_hop(xff).unwrap_or_else(|| peer_ip.to_string());
    if !allowed(&ip) {
        eprintln!("{} BLOCK {} {}", chrono::Utc::now().to_rfc3339(), ip, path);
        return Err((403, "Forbidden"));
    }
    Ok(())
}

// actix-web middleware
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::Error;
use futures_util::future::{ok, Ready, LocalBoxFuture};
use std::rc::Rc;

pub struct Wrap;
impl Wrap { pub fn new() -> Self { Wrap } }
pub fn wrap() -> Wrap { Wrap }

impl<S, B> Transform<S, ServiceRequest> for Wrap
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = WrapMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    fn new_transform(&self, service: S) -> Self::Future {
        ok(WrapMiddleware { service: Rc::new(service) })
    }
}

pub struct WrapMiddleware<S> { service: Rc<S> }
impl<S, B> Service<ServiceRequest> for WrapMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;
    fn poll_ready(&self, ctx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        Box::pin(async move {
            let peer = req.connection_info().peer_addr().unwrap_or_default().to_string();
            let xff = req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok());
            if let Err((_code, _msg)) = deny_unless_allowed(req.method().as_str(), req.path(), &peer, xff) {
                use actix_web::HttpResponse;
                return Ok(req.into_response(HttpResponse::Forbidden().finish().map_into_right_body()));
            }
            svc.call(req).await
        })
    }
}
''')

# ---------- helpers ----------
def _print(tag, path):
    print(f"{tag:>4} | {path}")

def list_files(root: Path, ext: str):
    ext = ext.lower()
    skip = {"node_modules", "vendor", "venv", ".git", "target", "bin", "obj", "__pycache__"}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip for part in p.parts):
            continue
        if p.suffix.lower() == ext:
            yield p

def ensure_backup(path: Path):
    bak = path.with_suffix(path.suffix + ".bak")
    if not bak.exists():
        shutil.copy2(path, bak)

# --- language-specific helpers (filters) ---
def is_go_main_dir(d: Path) -> bool:
    """true if dir has package main AND a func main()"""
    found_pkg_main = False
    found_main_func = False
    for f in d.glob("*.go"):
        if f.name.endswith("_test.go"):
            continue
        try:
            txt = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if re.search(r'(?m)^\s*package\s+main\b', txt):
            found_pkg_main = True
        if re.search(r'(?m)^\s*func\s+main\s*\(\s*\)\s*{', txt):
            found_main_func = True
    return found_pkg_main and found_main_func

def is_rust_bin_project(d: Path) -> bool:
    """true if Cargo.toml exists and src/main.rs exists"""
    return (d / "Cargo.toml").exists() and (d / "src" / "main.rs").exists()

# ---------- inject / generate ----------
def inject_php(file_path: Path, allow_list, log_path, dry=False):
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        _print("err", f"{file_path} (read: {e})")
        return False

    if MARK_PHP in text[:1000]:
        _print("skip", f"{file_path}")
        return False

    allow_php = "[" + ", ".join(repr(x) for x in allow_list) + "]"
    log_php = repr(log_path) if os.path.isabs(log_path) else "__DIR__ . '/' . " + repr(log_path)

    snippet = (PHP_SNIPPET_TEMPLATE
               .replace("{MARK}", MARK_PHP)
               .replace("{ALLOW_LIST}", allow_php)
               .replace("{LOG_PATH_PHP}", log_php))

    new_text = snippet + "\n" + text
    if dry:
        _print("dry", f"{file_path}")
        return True
    try:
        ensure_backup(file_path)
        file_path.write_text(new_text, encoding="utf-8")
        _print("php", f"{file_path}")
        return True
    except Exception as e:
        _print("err", f"{file_path} (write: {e})")
        return False

def generate_go_stub(dir_path: Path, allow_list, dry=False):
    stub = dir_path / GO_STUB_NAME
    if stub.exists():
        _print("skip", stub)
        return False
    allow_go = ", ".join(f'"{x}"' for x in allow_list)
    body = GO_STUB_TEMPLATE.substitute(allow_list_go=allow_go)
    if dry:
        _print("dry", stub)
        return True
    try:
        stub.write_text(body, encoding="utf-8")
        _print(" go", stub)
        return True
    except Exception as e:
        _print("err", f"{stub} (write: {e})")
        return False

def generate_rs_stub(dir_path: Path, allow_list, dry=False):
    # only for bin crates (src/main.rs)
    if not is_rust_bin_project(dir_path):
        return False
    target_dir = dir_path / "src"
    stub = target_dir / RS_STUB_NAME
    if stub.exists():
        _print("skip", stub)
        return False
    allow_rs = ", ".join(f'r#"{x}"#' for x in allow_list)
    body = RS_STUB_TEMPLATE.substitute(allow_list_rs=allow_rs)
    if dry:
        _print("dry", stub)
        return True
    try:
        cargo_toml = dir_path / "Cargo.toml"
        if cargo_toml.exists():
            try:
                txt = cargo_toml.read_text(encoding="utf-8")
                add = False
                if "once_cell" not in txt:
                    txt += '\n[dependencies]\nonce_cell = "1"\n'
                    add = True
                if "chrono" not in txt:
                    if "[dependencies]" in txt:
                        txt += 'chrono = "0.4"\n'
                    else:
                        txt += '\n[dependencies]\nchrono = "0.4"\n'
                    add = True
                if add:
                    ensure_backup(cargo_toml)
                    cargo_toml.write_text(txt, encoding="utf-8")
                    _print(" rs", f"{cargo_toml} (deps)")
            except Exception:
                pass
        (target_dir).mkdir(parents=True, exist_ok=True)
        stub.write_text(body, encoding="utf-8")
        _print(" rs", stub)
        return True
    except Exception as e:
        _print("err", f"{stub} (write: {e})")
        return False

# ---------- CLI ----------
def parse_args():
    p = argparse.ArgumentParser(
        description="Add IP allowlist guard to PHP files; drop Go/Rust stubs (only for main/bin targets)."
    )
    p.add_argument("root", help="scan root")
    p.add_argument("--allow", action="append", required=True, help="IP or CIDR (repeatable)")
    p.add_argument("--log", default="non_whitelisted.log", help="PHP block log path")
    p.add_argument("--dry-run", action="store_true", help="show actions only")
    p.add_argument("--no-go-stub", action="store_true", help="skip Go stub")
    p.add_argument("--no-rs-stub", action="store_true", help="skip Rust stub")
    return p.parse_args()

def main():
    args = parse_args()
    root = Path(args.root).resolve()
    if not root.exists():
        print(f"root not found: {root}", file=sys.stderr)
        sys.exit(1)

    # PHP
    php_count = 0
    for f in list_files(root, ".php"):
        if inject_php(f, args.allow, args.log, args.dry_run):
            php_count += 1

    # Go — only dirs that are real binaries
    if not args.no_go_stub:
        candidate_dirs = {p.parent for p in list_files(root, ".go")}
        main_dirs = sorted(d for d in candidate_dirs if is_go_main_dir(d))
        for d in main_dirs:
            generate_go_stub(d, args.allow, args.dry_run)

    # Rust — only crates with Cargo.toml + src/main.rs
    if not args.no_rs_stub:
        for cargo in root.rglob("Cargo.toml"):
            proj = cargo.parent
            if is_rust_bin_project(proj):
                generate_rs_stub(proj, args.allow, args.dry_run)

    print("done (dry)" if args.dry_run else f"done | php:{php_count}")

if __name__ == "__main__":
    main()

# ------------------------------------------------------------
# How to wire the generated stubs
#
# PHP
# - Nothing to do. The guard is injected at the top of every *.php file.
#
# Go (net/http)
# - The stub file `zz_ip_whitelist.go` defines:  func Wrap(next http.Handler) http.Handler
# - Use it to wrap the handler you pass to the server.
#   * Default mux:
#       http.ListenAndServe(":8080", Wrap(http.DefaultServeMux))
#   * Custom mux:
#       mux := http.NewServeMux()
#       http.ListenAndServe(":8080", Wrap(mux))
#   * http.Server:
#       srv := &http.Server{Addr: ":8080", Handler: Wrap(mux)}
#       srv.ListenAndServe()
#   * Frameworks (gin/echo/chi/gorilla):
#       http.ListenAndServe(":8080", Wrap(routerOrEngine))
#     (If you do this, don’t call r.Run() / e.Start().)
# - The stub is only written in dirs with `package main` + `func main()`.
#
# Rust (actix-web v4)
# - The stub file `src/ip_whitelist.rs` exports:  pub fn wrap() -> Wrap
# - In src/main.rs:
#       mod ip_whitelist;
#       use ip_whitelist::wrap;
#   Then in the server builder:
#       HttpServer::new(|| {
#           App::new()
#               .wrap(wrap())
#               .service(...)
#       })
#
# Quick test
# - Send a request with a fake X-Forwarded-For to see a 403:
#     curl -i -H "X-Forwarded-For: 8.8.8.8" http://127.0.0.1:<port>/
# ------------------------------------------------------------
