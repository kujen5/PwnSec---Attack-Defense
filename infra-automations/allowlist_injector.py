#!/usr/bin/env python3
import argparse, os, sys, re, shutil
from pathlib import Path
from string import Template

# ---- markers / filenames -----------------------------------------------------
MARK_PHP = "/* wl:php */"
GO_STUB_NAME = "zz_ip_whitelist.go"
RS_STUB_NAME = "ip_whitelist.rs"

# ---- PHP guard snippet -------------------------------------------------------
PHP_SNIPPET_TEMPLATE = Template(r'''<?php ${MARK}
$__WL = ${ALLOW_LIST};
$__LOG = ${LOG_PATH_PHP};

function __wl_first_hop($xff) {
    if (!$xff) return null;
    $p = explode(',', $xff, 2);
    return trim($p[0]);
}
function __wl_ip() {
    $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null;
    $cand = __wl_first_hop($xff);
    if ($cand) return $cand;
    $peer = $_SERVER['REMOTE_ADDR'] ?? '';
    $peer = explode(':', $peer)[0];  // strip :port
    return $peer;
}
function __wl_cidr_match($ip, $cidr) {
    if (strpos($cidr, '/') === false) return $ip === $cidr;
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) return false;
    list($sub, $mask) = explode('/', $cidr, 2);
    $mask = (int)$mask;
    $ipL = ip2long($ip);
    $subL = ip2long($sub);
    $maskL = -1 << (32 - $mask);
    return ($ipL & $maskL) === ($subL & $maskL);
}
function __wl_allowed($ip, $allow) {
    foreach ($allow as $a) {
        if (__wl_cidr_match($ip, $a)) return true;
    }
    return false;
}
function __wl_block($ip) {
    global $__LOG;
    $line = date('c')." BLOCK ".$ip." ".($_SERVER['REQUEST_METHOD']??'')." ".($_SERVER['REQUEST_URI']??'')."\n";
    if ($__LOG && @file_put_contents($__LOG, $line, FILE_APPEND) === false) { error_log($line); }
    http_response_code(403);
    exit('Forbidden');
}
function __wl_enforce() {
    global $__WL;
    $ip = __wl_ip();
    if (!__wl_allowed($ip, $__WL)) { __wl_block($ip); }
}
__wl_enforce();
''')

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

# ---- Rust stub (Actix v4 middleware) ----------------------------------------
RS_SNIPPET_TEMPLATE = Template(r'''use actix_web::{
    body::{EitherBody, MessageBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use once_cell::sync::Lazy;
use std::{
    net::Ipv4Addr,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
};

static ALLOW: Lazy<Arc<Vec<String>>> =
    Lazy::new(|| Arc::new(vec![${ALLOW_VEC}]));

fn first_hop(xff: Option<&str>) -> Option<String> {
    xff.and_then(|v| v.split(',').next().map(|s| s.trim().to_string()))
}

pub fn allowed(ip: &str) -> bool {
    if ALLOW.iter().any(|a| a == ip) { return true; }
    if let Ok(ipv4) = Ipv4Addr::from_str(ip) {
        for a in ALLOW.iter() {
            if let Some((sub, mask)) = a.split_once('/') {
                if let (Ok(s), Ok(m)) = (Ipv4Addr::from_str(sub), mask.parse::<u32>()) {
                    let m = (!0u32) << (32 - m.min(32));
                    if (u32::from(ipv4) & m) == (u32::from(s) & m) { return true; }
                }
            }
        }
    }
    false
}

pub fn deny_unless_allowed(
    _method: &str,
    _path: &str,
    peer_ip: &str,
    xff: Option<&str>,
) -> Result<(), (u16, &'static str)> {
    let peer = peer_ip.split(':').next().unwrap_or(peer_ip);
    let candidate = first_hop(xff).unwrap_or_else(|| peer.to_string());
    if allowed(&candidate) { Ok(()) } else { Err((403, "Forbidden")) }
}

pub struct Wrap;
pub fn wrap() -> Wrap { Wrap }

impl<S, B> Transform<S, ServiceRequest> for Wrap
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = WrapMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(WrapMiddleware { service }))
    }
}

pub struct WrapMiddleware<S> { service: S }

impl<S, B> Service<ServiceRequest> for WrapMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let peer = req.connection_info().peer_addr().unwrap_or_default().to_string();
        let xff = req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok());

        if let Err((_c, _m)) = deny_unless_allowed(req.method().as_str(), req.path(), &peer, xff) {
            let resp = HttpResponse::Forbidden().finish().map_into_right_body();
            return Box::pin(async move { Ok(req.into_response(resp)) });
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}
''')

# ================== PYTHON WEB PART (ADDED) ==================
PY_STUB_NAME = "ip_whitelist.py"

PY_STUB_TEMPLATE = Template(r'''# ip_whitelist.py
import ipaddress, os

ALLOW = ${ALLOW_LIST_PY}
# Optional override via env: ALLOW_CSV="1.2.3.4,10.0.0.0/8"
if os.getenv("ALLOW_CSV"):
    ALLOW = [s.strip() for s in os.getenv("ALLOW_CSV").split(",") if s.strip()]

def _first_hop(xff: str | None) -> str | None:
    if not xff: return None
    return xff.split(",", 1)[0].strip()

def _allowed(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for a in ALLOW:
        try:
            if "/" in a:
                if ip_obj in ipaddress.ip_network(a, strict=False): return True
            else:
                if ip_obj == ipaddress.ip_address(a): return True
        except Exception:
            pass
    return False

# ----- WSGI (Flask, Django runserver etc.)
class IPAllowlistWSGI:
    def __init__(self, app): self.app = app
    def __call__(self, environ, start_response):
        xff = environ.get("HTTP_X_FORWARDED_FOR")
        peer = (environ.get("REMOTE_ADDR") or "").split(":")[0]
        cand = _first_hop(xff) or peer
        if not _allowed(cand):
            start_response("403 Forbidden", [("Content-Type","text/plain")])
            return [b"Forbidden"]
        return self.app(environ, start_response)

# ----- ASGI (FastAPI/Starlette/Django ASGI)
class IPAllowlistASGI:
    def __init__(self, app): self.app = app
    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in (scope.get("headers") or [])}
        xff = headers.get("x-forwarded-for")
        peer = (scope.get("client") or ("", 0))[0]
        cand = _first_hop(xff) or peer
        if not _allowed(cand):
            await send({"type":"http.response.start","status":403,"headers":[(b"content-type", b"text/plain")]})
            await send({"type":"http.response.body","body":b"Forbidden"})
            return
        return await self.app(scope, receive, send)

# ----- Django middleware
class DjangoIPAllowlist:
    def __init__(self, get_response): self.get_response = get_response
    def __call__(self, request):
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        peer = (request.META.get("REMOTE_ADDR") or "").split(":")[0]
        cand = _first_hop(xff) or peer
        if not _allowed(cand):
            from django.http import HttpResponseForbidden
            return HttpResponseForbidden("Forbidden")
        return self.get_response(request)
''')

def is_python_app_dir(d: Path) -> bool:
    """Heuristic: treat as app dir if it contains common entry files."""
    names = {"app.py", "main.py", "wsgi.py", "asgi.py", "manage.py"}
    return any((d / n).exists() for n in names)

def write_py_stub(d: Path, allow_list, dry_run=False):
    out = d / PY_STUB_NAME
    if out.exists():
        print(f"[py] exists -> {out} (skip)")
        return False
    code = PY_STUB_TEMPLATE.substitute(ALLOW_LIST_PY=repr(list(allow_list)))
    if dry_run:
        print(f"[dry-run] write Python stub -> {out}")
        return True
    out.write_text(code, encoding="utf-8")
    print(f"[py] wrote stub -> {out}")
    return True
# ================== END PYTHON WEB PART ======================

# ---- helpers -----------------------------------------------------------------
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

def list_files(root: Path, ext: str):
    for p in root.rglob(f"*{ext}"):
        if p.is_file():
            yield p

def inject_php(f: Path, allow_list, log_path_php, dry_run=False):
    txt = f.read_text(encoding="utf-8", errors="ignore")
    if MARK_PHP in txt:
        return False
    snippet = PHP_SNIPPET_TEMPLATE.substitute(
        MARK=MARK_PHP,
        ALLOW_LIST=repr(list(allow_list)),
        LOG_PATH_PHP=repr(str(log_path_php)),
    )
    new_txt = snippet + "\n" + txt
    if dry_run:
        print(f"[dry-run] inject PHP guard -> {f}")
        return True
    f.write_text(new_txt, encoding="utf-8")
    print(f"[php] injected -> {f}")
    return True

def is_go_main_dir(d: Path) -> bool:
    """Heuristic: directory has package main + func main()"""
    found_pkg_main = False
    found_main_func = False
    for g in d.glob("*.go"):
        if g.name.endswith("_test.go"): continue
        t = g.read_text(encoding="utf-8", errors="ignore")
        if re.search(r'(?m)^\s*package\s+main\s*$', t): found_pkg_main = True
        if re.search(r'func\s+main\s*\(', t): found_main_func = True
    return found_pkg_main and found_main_func

def write_go_stub(d: Path, allow_list, dry_run=False):
    allow_csv = ",".join([repr(a) for a in allow_list])
    code = GO_STUB_TEMPLATE.substitute(ALLOW_CSV=allow_csv)
    out = d / GO_STUB_NAME
    if dry_run:
        print(f"[dry-run] write Go stub -> {out}")
        return
    out.write_text(code, encoding="utf-8")
    print(f"[go] wrote stub -> {out}")

def is_rust_main_dir(d: Path) -> bool:
    return (d / "Cargo.toml").exists() and (d / "src" / "main.rs").exists()

def ensure_rust_deps(cargo_toml_path: Path):
    if not cargo_toml_path.exists():
        return
    txt = cargo_toml_path.read_text(encoding="utf-8", errors="ignore")

    # merge duplicate [dependencies] sections (keep first header)
    parts = re.split(r'(?m)^\[dependencies\]\s*$', txt)
    if len(parts) > 2:
        head, first_block, *rest = parts
        merged_block = first_block + "\n" + "\n".join(rest)
        txt = "[dependencies]".join([head, merged_block])

    # ensure dependencies; add if missing (harmless if already present)
    def ensure_line(t, key, val):
        if re.search(rf'(?m)^\s*{re.escape(key)}\s*=', t) is None:
            return re.sub(r'(?m)^\[dependencies\]\s*$', f"[dependencies]\n{key} = {val}", t, count=1)
        return t

    if re.search(r'(?m)^\[dependencies\]\s*$', txt) is None:
        txt += "\n[dependencies]\n"

    txt = ensure_line(txt, "futures-util", '"0.3"')
    txt = ensure_line(txt, "once_cell", '"1"')
    txt = ensure_line(txt, "actix-web", '"4"')

    cargo_toml_path.write_text(txt, encoding="utf-8")
    print(f"[rust] ensured deps in -> {cargo_toml_path}")

def write_rs_stub(d: Path, allow_list, dry_run=False):
    allow_vec = ", ".join([f'"{a}".to_string()' for a in allow_list])
    code = RS_SNIPPET_TEMPLATE.substitute(ALLOW_VEC=allow_vec)
    out = d / "src" / RS_STUB_NAME
    if dry_run:
        print(f"[dry-run] write Rust stub -> {out}")
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(code, encoding="utf-8")
    ensure_rust_deps(d / "Cargo.toml")
    print(f"[rust] wrote stub -> {out}")

def generate_go_stub(dir_path: Path, allow_list, dry=False):
    stub = dir_path / GO_STUB_NAME
    if stub.exists():
        print("skip", stub)
        return False
    allow_go = ", ".join(f'"{x}"' for x in allow_list)
    body = GO_STUB_TEMPLATE.substitute(allow_list_go=allow_go)
    if dry:
        print("dry", stub)
        return True
    try:
        stub.write_text(body, encoding="utf-8")
        print(" go", stub)
        return True
    except Exception as e:
        print("err", f"{stub} (write: {e})")
        return False

# ---- main --------------------------------------------------------------------
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

    # Go — only real binaries (package main + func main)
    if not args.no_go_stub:
        candidate_dirs = {p.parent for p in list_files(root, ".go")}
        main_dirs = sorted(d for d in candidate_dirs if is_go_main_dir(d))
        for d in main_dirs:
            generate_go_stub(d, args.allow, args.dry_run)

    # Rust — only crates that look like binaries (have src/main.rs)
    if not args.no_rs_stub:
        for cargo in root.rglob("Cargo.toml"):
            d = cargo.parent
            if is_rust_main_dir(d):
                write_rs_stub(d, args.allow, args.dry_run)

    # ---------- Python (Flask/FastAPI/Django) -------------
    py_candidate_dirs = {p.parent for p in list_files(root, ".py")}
    for d in sorted(py_candidate_dirs):
        if is_python_app_dir(d):
            write_py_stub(d, args.allow, args.dry_run)

    # Hints
    print("\n# ------------------------------------------------------------")
    print("# How to wire the generated stubs")
    print("#")
    print("# PHP")
    print("# - Nothing to do. The guard is injected at the top of every *.php file.")
    print("#")
    print("# Go (net/http)")
    print("# - The stub file `zz_ip_whitelist.go` defines:  func Wrap(next http.Handler) http.Handler")
    print("# - Use it to wrap the handler you pass to the server.")
    print("#   * Default mux:      http.ListenAndServe(\":8080\", Wrap(http.DefaultServeMux))")
    print("#   * Custom mux:       mux := http.NewServeMux(); http.ListenAndServe(\":8080\", Wrap(mux))")
    print("#   * http.Server:      srv := &http.Server{Addr: \":8080\", Handler: Wrap(mux)}")
    print("#")
    print("# Rust (actix-web v4)")
    print("# - The stub file `src/ip_whitelist.rs` exports:  pub fn wrap() -> Wrap")
    print("# - In src/main.rs:")
    print("#       mod ip_whitelist;")
    print("#       use ip_whitelist::wrap;")
    print("#   Then in the server builder:")
    print("#       HttpServer::new(|| App::new().wrap(wrap()).service(...))")
    print("#")
    print("# Python (Flask/FastAPI/Django)")
    print("# - Stub `ip_whitelist.py` provides:")
    print("#   * WSGI:  IPAllowlistWSGI  -> Flask/Django runserver")
    print("#   * ASGI:  IPAllowlistASGI  -> FastAPI/Starlette/Django ASGI")
    print("#   * Django middleware: DjangoIPAllowlist")
    print("# - Wire examples:")
    print("#   Flask:   app.wsgi_app = IPAllowlistWSGI(app.wsgi_app)")
    print("#   FastAPI: app = IPAllowlistASGI(app)")
    print("#   Django:  add '...DjangoIPAllowlist' to MIDDLEWARE")
    print("#")
    print("# Quick test")
    print("# - Send a request with a fake X-Forwarded-For to see a 403:")
    print("#     curl -i -H \"X-Forwarded-For: 8.8.8.8\" http://127.0.0.1:<port>/")
    print("# ------------------------------------------------------------")

if __name__ == "__main__":
    main()
