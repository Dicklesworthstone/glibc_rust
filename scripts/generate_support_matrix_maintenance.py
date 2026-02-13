#!/usr/bin/env python3
"""generate_support_matrix_maintenance.py — bd-3g4p

Automated support matrix maintenance: validates that the implementation
status of each symbol in support_matrix.json matches code reality and
links symbols to conformance fixture coverage.

Three validation passes:
  1. STATUS VALIDATION: Code patterns match declared status.
  2. CONFORMANCE LINKAGE: Symbols linked to fixture test cases.
  3. COVERAGE REPORT: Per-module and per-status coverage statistics.

Outputs a JSON maintenance report to stdout (or --output file).
"""
import json
import os
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
MATRIX_PATH = REPO_ROOT / "support_matrix.json"
ABI_SRC = REPO_ROOT / "crates" / "frankenlibc-abi" / "src"
FIXTURE_DIR = REPO_ROOT / "tests" / "conformance" / "fixtures"

# Patterns indicating host glibc calls
LIBC_CALL_PATTERN = re.compile(r'\blibc::(\w+)\b')
# Patterns indicating raw syscall usage
SYSCALL_PATTERN = re.compile(
    r'(?:crate::syscall::|super::syscall::|syscall!|syscall_raw|'
    r'libc::syscall\b|libc::SYS_|__NR_)'
)
# Patterns indicating stub/unimplemented (explicit Rust stub macros only;
# `return -1` is a normal POSIX error return, not a stub indicator).
STUB_PATTERNS = [
    re.compile(r'\btodo!\b'),
    re.compile(r'\bunimplemented!\b'),
]
# Data symbols (statics, not functions)
DATA_SYMBOLS = {"stdin", "stdout", "stderr"}


def load_matrix():
    with open(MATRIX_PATH, encoding="utf-8") as f:
        return json.load(f)


def load_fixtures():
    """Scan fixture directory, returning a map of function_name → fixture info."""
    fixture_map = {}  # function_name -> list of {file, case_name, mode}
    if not FIXTURE_DIR.is_dir():
        return fixture_map

    for fpath in sorted(FIXTURE_DIR.glob("*.json")):
        try:
            with fpath.open(encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        for case in data.get("cases", []):
            func = case.get("function", "")
            name = case.get("name", "")
            mode = case.get("mode", "unknown")
            if func:
                # Normalize: strip class prefix (e.g., "PressureSensor::observe" → "observe")
                bare_func = func.split("::")[-1] if "::" in func else func
                entry = {"file": fpath.name, "case": name, "mode": mode}
                fixture_map.setdefault(bare_func, []).append(entry)
                if bare_func != func:
                    fixture_map.setdefault(func, []).append(entry)

    return fixture_map


def read_module_source(module_name):
    """Read ABI module source file content."""
    src_path = ABI_SRC / f"{module_name}.rs"
    if not src_path.is_file():
        return None
    return src_path.read_text(encoding="utf-8")


def extract_function_body(source, fn_name):
    """Extract approximate function body for a given fn name.

    Returns the text from 'fn name(' to the next function definition or EOF.
    This is approximate but sufficient for pattern matching.
    """
    pattern = re.compile(rf'\bfn\s+{re.escape(fn_name)}\s*\(')
    match = pattern.search(source)
    if not match:
        return None

    start = match.start()
    # Find next function definition or end of file
    next_fn = re.search(r'\n\s*(?:pub\s+)?(?:unsafe\s+)?(?:extern\s+"C"\s+)?fn\s+\w+\s*\(',
                        source[match.end():])
    if next_fn:
        end = match.end() + next_fn.start()
    else:
        end = len(source)

    return source[start:end]


def is_type_or_constant(name):
    """Heuristic: libc:: references that are types or constants, not function calls.

    Types: end in _t, start with lowercase c_ prefix, are ALL_CAPS, or match
    known struct/enum patterns.
    Constants: ALL_CAPS or start with uppercase (e.g., EINVAL, AF_INET, SIG_DFL).
    Functions: lowercase names like 'malloc', 'write', 'pthread_create'.
    """
    if name.endswith("_t"):
        return True
    if name.startswith("c_"):
        return True
    # ALL_CAPS or starts with uppercase = constant or type
    if name[0].isupper():
        return True
    # Known struct names that are lowercase
    lowercase_types = {
        "stat", "dirent", "dirent64", "passwd", "group", "spwd",
        "termios", "winsize", "addrinfo", "hostent", "servent",
        "protoent", "linger", "timezone", "tm", "iovec", "msghdr",
        "epoll_event", "pollfd", "glob_t",
    }
    return name in lowercase_types


def validate_status(symbol, status, module, source):
    """Validate that a symbol's code matches its declared status.

    Returns (is_valid, findings: list of str).
    """
    if symbol in DATA_SYMBOLS:
        return True, []

    body = extract_function_body(source, symbol)
    if body is None:
        return True, [f"function body not found (may use alternate pattern)"]

    findings = []

    if status == "Implemented":
        # Should NOT have libc:: host calls (except libc type references)
        libc_calls = LIBC_CALL_PATTERN.findall(body)
        # Filter out type-only references (common pattern: libc::c_int etc.)
        type_refs = {"c_int", "c_uint", "c_long", "c_ulong", "c_char",
                     "c_void", "c_double", "c_float", "size_t", "ssize_t",
                     "off_t", "pid_t", "uid_t", "gid_t", "mode_t",
                     "socklen_t", "sockaddr", "sigset_t", "timespec",
                     "timeval", "stat", "dirent", "DIR", "FILE",
                     "pthread_t", "pthread_attr_t", "pthread_mutex_t",
                     "pthread_mutexattr_t", "pthread_cond_t",
                     "pthread_condattr_t", "pthread_rwlock_t",
                     "pthread_key_t", "pthread_once_t",
                     "PTHREAD_MUTEX_INITIALIZER", "PTHREAD_COND_INITIALIZER",
                     "PTHREAD_RWLOCK_INITIALIZER", "CLOCK_REALTIME",
                     "CLOCK_MONOTONIC", "EINVAL", "ENOMEM", "ENOSYS",
                     "EAGAIN", "EDEADLK", "EBUSY", "EPERM", "ESRCH",
                     "ENOENT", "ERANGE", "EACCES", "EEXIST", "EINTR",
                     "EBADF", "EFAULT", "EMFILE", "ENFILE", "E2BIG",
                     "EISDIR", "ENOTDIR", "ENOTEMPTY", "EXDEV", "ELOOP",
                     "ENAMETOOLONG", "EOF",
                     "AF_INET", "AF_INET6", "AF_UNIX", "SOCK_STREAM",
                     "SOCK_DGRAM", "SOL_SOCKET", "SO_REUSEADDR",
                     "O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT",
                     "O_TRUNC", "O_APPEND", "O_NONBLOCK", "O_CLOEXEC",
                     "SEEK_SET", "SEEK_CUR", "SEEK_END",
                     "F_GETFL", "F_SETFL", "F_DUPFD", "F_GETFD", "F_SETFD",
                     "STDIN_FILENO", "STDOUT_FILENO", "STDERR_FILENO",
                     "EXIT_SUCCESS", "EXIT_FAILURE", "NULL",
                     "RLIMIT_NOFILE", "RLIM_INFINITY",
                     # Network struct/type references
                     "addrinfo", "sockaddr_in", "sockaddr_in6",
                     "sockaddr_un", "sockaddr_storage", "in_addr",
                     "in6_addr", "hostent", "servent", "protoent",
                     "linger", "ip_mreq",
                     # Passwd/group struct references
                     "passwd", "group", "spwd",
                     # Terminal struct references
                     "termios", "winsize",
                     # Locale/iconv references
                     "locale_t", "nl_item",
                     # Misc struct/type references
                     "rlimit", "rusage", "utsname", "sysinfo",
                     "epoll_event", "pollfd", "fd_set",
                     "Dl_info", "dl_phdr_info",
                     "glob_t", "regex_t", "regmatch_t",
                     "sem_t", "key_t", "shmid_ds", "semid_ds", "msqid_ds",
                     "sigaction", "stack_t", "siginfo_t",
                     "itimerval", "itimerspec",
                     "statvfs", "statfs",
                     "tm", "timezone",
                     "DIR",
                     }
        fn_calls = [c for c in libc_calls
                    if c not in type_refs and not is_type_or_constant(c)]
        if fn_calls:
            unique_calls = sorted(set(fn_calls))
            calls_str = ", ".join(unique_calls[:5])
            findings.append("Implemented but calls libc::{" + calls_str + "}")

        # Should NOT have stub patterns
        for pat in STUB_PATTERNS:
            if pat.search(body):
                findings.append(f"Implemented but contains stub pattern: {pat.pattern}")

    elif status == "RawSyscall":
        # RawSyscall functions use libc::syscall() and libc::SYS_* constants
        # which IS the raw syscall path (not glibc function calls).
        # We check that they don't call actual glibc library functions.
        libc_calls = LIBC_CALL_PATTERN.findall(body)
        # libc::syscall and libc::SYS_* are the raw syscall mechanism
        syscall_ok = re.compile(r'^(?:syscall|SYS_\w+)$')
        type_refs = {"c_int", "c_uint", "c_long", "c_ulong", "c_char",
                     "c_void", "c_double", "c_float", "size_t", "ssize_t",
                     "off_t", "pid_t", "uid_t", "gid_t", "mode_t",
                     "socklen_t", "sockaddr", "timespec", "timeval",
                     "stat", "dirent", "iovec", "msghdr", "loff_t",
                     "EINVAL", "ENOMEM", "ENOSYS", "EAGAIN", "EBADF",
                     "EFAULT", "EINTR", "EACCES", "ENOENT", "EPERM",
                     "EEXIST", "EISDIR", "ENOTDIR", "ENOTEMPTY",
                     "EBUSY", "ENFILE", "EMFILE", "ERANGE", "E2BIG",
                     "ELOOP", "ENAMETOOLONG", "EXDEV", "ESPIPE",
                     "O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT",
                     "O_TRUNC", "O_APPEND", "O_NONBLOCK", "O_CLOEXEC",
                     "O_DIRECTORY", "O_NOFOLLOW", "O_EXCL",
                     "AT_FDCWD", "AT_REMOVEDIR", "AT_SYMLINK_NOFOLLOW",
                     "SEEK_SET", "SEEK_CUR", "SEEK_END",
                     "AF_INET", "AF_INET6", "AF_UNIX", "SOCK_STREAM",
                     "SOCK_DGRAM", "SOCK_CLOEXEC", "SOCK_NONBLOCK",
                     "SOL_SOCKET", "SO_REUSEADDR", "SO_ERROR",
                     "MSG_DONTWAIT", "MSG_NOSIGNAL", "SHUT_RDWR",
                     "SHUT_RD", "SHUT_WR",
                     "F_GETFL", "F_SETFL", "F_DUPFD", "F_GETFD", "F_SETFD",
                     "FD_CLOEXEC", "FIONBIO",
                     "CLOCK_REALTIME", "CLOCK_MONOTONIC",
                     "SIGCHLD", "SIG_DFL", "SIG_IGN",
                     "WNOHANG", "WUNTRACED",
                     "PROT_READ", "PROT_WRITE", "PROT_EXEC", "PROT_NONE",
                     "MAP_PRIVATE", "MAP_ANONYMOUS", "MAP_SHARED", "MAP_FIXED",
                     "MAP_FAILED", "MREMAP_MAYMOVE",
                     "RLIMIT_NOFILE", "RLIM_INFINITY",
                     "GRND_NONBLOCK", "GRND_RANDOM",
                     "R_OK", "W_OK", "X_OK", "F_OK",
                     "DT_DIR", "DT_REG", "DT_LNK", "DT_UNKNOWN",
                     "STDIN_FILENO", "STDOUT_FILENO", "STDERR_FILENO",
                     "EXIT_SUCCESS", "EXIT_FAILURE",
                     "POLLIN", "POLLOUT", "POLLERR", "POLLHUP",
                     "EPOLL_CTL_ADD", "EPOLL_CTL_DEL", "EPOLL_CTL_MOD",
                     "EPOLLIN", "EPOLLOUT", "EPOLLERR", "EPOLLHUP",
                     "RUSAGE_SELF", "RUSAGE_CHILDREN",
                     "TIOCGWINSZ", "TCSANOW", "TCSADRAIN", "TCSAFLUSH",
                     "c_ushort",
                     # Struct/type references used in syscall wrappers
                     "termios", "winsize", "rlimit", "rusage",
                     "utsname", "sysinfo", "statvfs", "statfs",
                     "epoll_event", "pollfd", "fd_set",
                     "sigaction", "stack_t", "siginfo_t", "sigset_t",
                     "itimerval", "itimerspec", "tm", "timezone",
                     "sockaddr_in", "sockaddr_in6", "sockaddr_un",
                     "sockaddr_storage", "in_addr", "in6_addr",
                     "linger", "ip_mreq", "addrinfo",
                     "DIR", "dirent64",
                     }
        glibc_calls = [c for c in libc_calls
                       if c not in type_refs
                       and not syscall_ok.match(c)
                       and not is_type_or_constant(c)]
        if glibc_calls:
            unique_calls = sorted(set(glibc_calls))
            calls_str = ", ".join(unique_calls[:5])
            findings.append("RawSyscall but calls glibc::{" + calls_str + "}")

    elif status == "GlibcCallThrough":
        # Should have libc:: references (function calls or type usage indicating
        # delegation to the host libc). We check broadly since many call-through
        # symbols delegate via helpers.
        libc_calls = LIBC_CALL_PATTERN.findall(body)
        if not libc_calls:
            findings.append("GlibcCallThrough but no libc:: references found")

    elif status == "Stub":
        # Should have stub patterns or deterministic failure return
        has_stub = any(pat.search(body) for pat in STUB_PATTERNS)
        if not has_stub:
            findings.append("Stub but no stub/unimplemented/todo pattern found")

    is_valid = len(findings) == 0
    return is_valid, findings


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Support matrix maintenance validator")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return

    matrix = load_matrix()
    symbols = matrix.get("symbols", [])
    fixture_map = load_fixtures()

    # Cache module sources
    module_cache = {}

    status_results = []
    linkage_results = []
    errors = 0
    warnings = 0

    # --- Pass 1: Status Validation ---
    status_valid = 0
    status_invalid = 0
    status_skipped = 0

    for entry in symbols:
        sym = entry["symbol"]
        st = entry.get("status", "unknown")
        module = entry.get("module", "unknown")

        if module not in module_cache:
            module_cache[module] = read_module_source(module)

        source = module_cache[module]
        if source is None:
            status_skipped += 1
            status_results.append({
                "symbol": sym,
                "status": st,
                "module": module,
                "valid": None,
                "findings": ["module source not found"],
            })
            continue

        is_valid, findings = validate_status(sym, st, module, source)
        if is_valid:
            status_valid += 1
        else:
            status_invalid += 1
            warnings += len(findings)

        status_results.append({
            "symbol": sym,
            "status": st,
            "module": module,
            "valid": is_valid,
            "findings": findings,
        })

    # --- Pass 2: Conformance Linkage ---
    linked = 0
    unlinked = 0

    for entry in symbols:
        sym = entry["symbol"]
        cases = fixture_map.get(sym, [])
        has_fixture = len(cases) > 0
        strict_cases = sum(1 for c in cases if c["mode"] in ("strict", "both"))
        hardened_cases = sum(1 for c in cases if c["mode"] in ("hardened", "both"))

        if has_fixture:
            linked += 1
        else:
            unlinked += 1

        linkage_results.append({
            "symbol": sym,
            "has_fixture": has_fixture,
            "fixture_count": len(cases),
            "strict_count": strict_cases,
            "hardened_count": hardened_cases,
            "fixtures": [c["file"] for c in cases[:5]],
        })

    # --- Pass 3: Coverage Statistics ---
    by_status = {}
    by_module = {}
    by_status_linked = {}

    for i, entry in enumerate(symbols):
        st = entry.get("status", "unknown")
        module = entry.get("module", "unknown")
        has_fix = linkage_results[i]["has_fixture"]

        by_status[st] = by_status.get(st, 0) + 1
        by_module.setdefault(module, {"total": 0, "linked": 0})
        by_module[module]["total"] += 1
        if has_fix:
            by_module[module]["linked"] += 1
            by_status_linked[st] = by_status_linked.get(st, 0) + 1

    coverage_pct = (linked / len(symbols) * 100) if symbols else 0
    status_valid_pct = (status_valid / len(symbols) * 100) if symbols else 0

    # Build report
    report = {
        "schema_version": "v1",
        "bead": "bd-3g4p",
        "generated_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_symbols": len(symbols),
            "status_validated": status_valid,
            "status_invalid": status_invalid,
            "status_skipped": status_skipped,
            "status_valid_pct": round(status_valid_pct, 1),
            "fixture_linked": linked,
            "fixture_unlinked": unlinked,
            "fixture_coverage_pct": round(coverage_pct, 1),
            "total_warnings": warnings,
        },
        "status_distribution": {
            st: {
                "count": by_status.get(st, 0),
                "fixture_linked": by_status_linked.get(st, 0),
            }
            for st in sorted(by_status.keys())
        },
        "module_coverage": {
            mod_name: {
                "total": info["total"],
                "linked": info["linked"],
                "coverage_pct": round(info["linked"] / info["total"] * 100, 1)
                if info["total"] > 0
                else 0,
            }
            for mod_name, info in sorted(by_module.items())
        },
        "status_validation_issues": [
            r for r in status_results if r.get("findings")
        ],
        "unlinked_symbols": [
            r["symbol"] for r in linkage_results if not r["has_fixture"]
        ],
    }

    output = json.dumps(report, indent=2) + "\n"

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        # Print summary to stderr
        print(f"Total symbols: {len(symbols)}", file=sys.stderr)
        print(f"Status valid: {status_valid}/{len(symbols)} ({status_valid_pct:.1f}%)",
              file=sys.stderr)
        print(f"Fixture linked: {linked}/{len(symbols)} ({coverage_pct:.1f}%)",
              file=sys.stderr)
        print(f"Warnings: {warnings}", file=sys.stderr)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(output)

    # Report generation always succeeds. Findings are informational
    # and consumed by the CI gate for threshold-based decisions.
    sys.exit(0)


def run_self_test():
    """Minimal self-test."""
    print("Self-test: loading matrix...")
    matrix = load_matrix()
    symbols = matrix.get("symbols", [])
    print(f"  {len(symbols)} symbols loaded")

    print("Self-test: loading fixtures...")
    fixtures = load_fixtures()
    print(f"  {len(fixtures)} fixture functions indexed")

    print("Self-test: status validation on first 3 symbols...")
    module_cache = {}
    for entry in symbols[:3]:
        sym = entry["symbol"]
        module = entry.get("module", "unknown")
        if module not in module_cache:
            module_cache[module] = read_module_source(module)
        source = module_cache[module]
        if source:
            is_valid, findings = validate_status(sym, entry["status"], module, source)
            mark = "✓" if is_valid else "✗"
            print(f"  {mark} {sym} ({entry['status']}): {findings or 'ok'}")
        else:
            print(f"  ? {sym}: source not found")

    print("Self-test: PASS")


if __name__ == "__main__":
    main()
