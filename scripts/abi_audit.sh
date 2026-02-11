#!/usr/bin/env bash
# ABI symbol audit: exported symbol list + support classification.
#
# Produces:
#   1. Machine-readable support_matrix.json
#   2. Human-readable summary to stdout
#
# Usage:
#   bash scripts/abi_audit.sh [--json-only]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUR_LIB="${PROJECT_ROOT}/target/release/libglibc_rs_abi.so"
ALT_LIB="/data/tmp/cargo-target/release/libglibc_rs_abi.so"
HOST_LIB="/usr/lib/x86_64-linux-gnu/libc.so.6"
MATRIX_OUT="${PROJECT_ROOT}/support_matrix.json"

JSON_ONLY=0
if [[ "${1:-}" == "--json-only" ]]; then
  JSON_ONLY=1
fi

# Use alternate target dir if default doesn't exist.
if [[ ! -f "${OUR_LIB}" ]] && [[ -f "${ALT_LIB}" ]]; then
  OUR_LIB="${ALT_LIB}"
fi

if [[ ! -f "${OUR_LIB}" ]]; then
  echo "ERROR: Library not found. Build with: cargo build --release -p glibc-rs-abi" >&2
  exit 1
fi

# ------------------------------------------------------------------
# Symbol classification database.
# Status: Implemented | RawSyscall | GlibcCallThrough | Stub
# PerfClass: strict_hotpath | hardened_hotpath | coldpath
# ------------------------------------------------------------------

declare -A SYM_STATUS
declare -A SYM_MODULE
declare -A SYM_PERF

# malloc_abi: Implemented (safe Rust allocator)
for s in malloc free calloc realloc posix_memalign memalign aligned_alloc; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="malloc_abi"
  SYM_PERF[$s]="strict_hotpath"
done

# string_abi: Implemented (safe Rust)
for s in memcpy memmove memset memcmp memchr memrchr \
         strlen strcmp strcpy strncpy strcat strncat \
         strchr strrchr strstr strtok strtok_r; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="string_abi"
  SYM_PERF[$s]="strict_hotpath"
done

# wchar_abi: Implemented (safe Rust)
for s in wcslen wcscpy wcsncpy wcscat wcscmp wcsncmp \
         wcschr wcsrchr wcsstr wmemcpy wmemmove wmemset wmemcmp wmemchr; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="wchar_abi"
  SYM_PERF[$s]="strict_hotpath"
done

# stdlib_abi: Implemented (safe Rust)
for s in atoi atol strtol strtoul exit atexit qsort bsearch; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="stdlib_abi"
  SYM_PERF[$s]="coldpath"
done

# errno_abi: Implemented (thread-local)
SYM_STATUS[__errno_location]="Implemented"
SYM_MODULE[__errno_location]="errno_abi"
SYM_PERF[__errno_location]="strict_hotpath"

# math_abi: Implemented (Rust std::f64)
for s in sin cos tan asin acos atan atan2 \
         exp log log10 pow fabs ceil floor round fmod \
         erf tgamma lgamma; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="math_abi"
  SYM_PERF[$s]="coldpath"
done

# ctype_abi: Implemented (lookup table)
for s in isalpha isdigit isalnum isspace isupper islower \
         isprint ispunct isxdigit toupper tolower; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="ctype_abi"
  SYM_PERF[$s]="strict_hotpath"
done

# stdio_abi: GlibcCallThrough (wraps system FILE* operations)
for s in fopen fclose fflush fgetc fputc fgets fputs fread fwrite \
         fseek ftell rewind feof ferror clearerr ungetc fileno \
         setvbuf setbuf putchar puts getchar perror \
         snprintf sprintf fprintf printf; do
  SYM_STATUS[$s]="GlibcCallThrough"
  SYM_MODULE[$s]="stdio_abi"
  SYM_PERF[$s]="coldpath"
done

# io_abi: RawSyscall
for s in dup dup2 pipe fcntl; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="io_abi"
  SYM_PERF[$s]="coldpath"
done

# unistd_abi: RawSyscall
for s in read write close lseek isatty getpid getppid getuid geteuid getgid getegid \
         stat fstat lstat access getcwd chdir fchdir \
         unlink rmdir link symlink readlink fsync fdatasync sleep usleep; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="unistd_abi"
  SYM_PERF[$s]="coldpath"
done

# socket_abi: RawSyscall
for s in socket bind listen accept connect send recv sendto recvfrom \
         shutdown setsockopt getsockopt getpeername getsockname; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="socket_abi"
  SYM_PERF[$s]="coldpath"
done

# inet_abi: Implemented (pure computation)
for s in htons htonl ntohs ntohl inet_pton inet_ntop inet_addr; do
  SYM_STATUS[$s]="Implemented"
  SYM_MODULE[$s]="inet_abi"
  SYM_PERF[$s]="coldpath"
done

# signal_abi: RawSyscall
for s in signal raise kill sigaction; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="signal_abi"
  SYM_PERF[$s]="coldpath"
done

# time_abi: RawSyscall
for s in time clock_gettime clock localtime_r; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="time_abi"
  SYM_PERF[$s]="coldpath"
done

# pthread_abi: Stub (wraps glibc pthread for now)
for s in pthread_self pthread_equal pthread_create pthread_join pthread_detach \
         pthread_mutex_init pthread_mutex_destroy pthread_mutex_lock pthread_mutex_trylock pthread_mutex_unlock \
         pthread_cond_init pthread_cond_destroy pthread_cond_wait pthread_cond_signal pthread_cond_broadcast \
         pthread_rwlock_init pthread_rwlock_destroy pthread_rwlock_rdlock pthread_rwlock_wrlock pthread_rwlock_unlock; do
  SYM_STATUS[$s]="GlibcCallThrough"
  SYM_MODULE[$s]="pthread_abi"
  SYM_PERF[$s]="strict_hotpath"
done

# resolv_abi: Stub (thin wrappers)
for s in getaddrinfo freeaddrinfo getnameinfo gai_strerror; do
  SYM_STATUS[$s]="Stub"
  SYM_MODULE[$s]="resolv_abi"
  SYM_PERF[$s]="coldpath"
done

# locale_abi: Stub
for s in setlocale localeconv; do
  SYM_STATUS[$s]="Stub"
  SYM_MODULE[$s]="locale_abi"
  SYM_PERF[$s]="coldpath"
done

# dlfcn_abi: GlibcCallThrough
for s in dlopen dlsym dlclose dlerror; do
  SYM_STATUS[$s]="GlibcCallThrough"
  SYM_MODULE[$s]="dlfcn_abi"
  SYM_PERF[$s]="coldpath"
done

# dirent_abi: RawSyscall
for s in opendir readdir closedir; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="dirent_abi"
  SYM_PERF[$s]="coldpath"
done

# resource_abi: RawSyscall
for s in getrlimit setrlimit; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="resource_abi"
  SYM_PERF[$s]="coldpath"
done

# termios_abi: RawSyscall
for s in tcgetattr tcsetattr cfgetispeed cfgetospeed cfsetispeed cfsetospeed \
         tcdrain tcflush tcflow tcsendbreak; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="termios_abi"
  SYM_PERF[$s]="coldpath"
done

# mmap_abi: RawSyscall
for s in mmap munmap mprotect msync madvise; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="mmap_abi"
  SYM_PERF[$s]="coldpath"
done

# poll_abi: RawSyscall
for s in poll ppoll select pselect; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="poll_abi"
  SYM_PERF[$s]="coldpath"
done

# process_abi: RawSyscall
for s in fork _exit execve execvp waitpid wait; do
  SYM_STATUS[$s]="RawSyscall"
  SYM_MODULE[$s]="process_abi"
  SYM_PERF[$s]="coldpath"
done

# Data symbols (stdio globals)
for s in stdin stdout stderr; do
  SYM_STATUS[$s]="GlibcCallThrough"
  SYM_MODULE[$s]="stdio_abi"
  SYM_PERF[$s]="coldpath"
done

# ------------------------------------------------------------------
# Extract actual exported symbols from our .so
# ------------------------------------------------------------------
our_syms=$(nm -D --defined-only "${OUR_LIB}" 2>/dev/null | awk '{print $NF}' | sort)
our_count=$(echo "${our_syms}" | wc -l)

# ------------------------------------------------------------------
# Build JSON support matrix
# ------------------------------------------------------------------
{
  echo "{"
  echo "  \"version\": 1,"
  echo "  \"generated_at_utc\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"library\": \"${OUR_LIB}\","
  echo "  \"total_exported\": ${our_count},"
  echo "  \"symbols\": ["

  first=1
  while IFS= read -r sym; do
    [[ -z "$sym" ]] && continue
    status="${SYM_STATUS[$sym]:-Unclassified}"
    module="${SYM_MODULE[$sym]:-unknown}"
    perf="${SYM_PERF[$sym]:-unknown}"

    if [[ $first -eq 0 ]]; then
      echo ","
    fi
    first=0
    printf '    {"symbol": "%s", "status": "%s", "module": "%s", "perf_class": "%s"}' \
      "$sym" "$status" "$module" "$perf"
  done <<< "${our_syms}"

  echo ""
  echo "  ],"

  # Summary counts
  impl=0; raw=0; glibc=0; stub=0; unclass=0
  while IFS= read -r sym; do
    [[ -z "$sym" ]] && continue
    case "${SYM_STATUS[$sym]:-Unclassified}" in
      Implemented) impl=$((impl + 1)) ;;
      RawSyscall) raw=$((raw + 1)) ;;
      GlibcCallThrough) glibc=$((glibc + 1)) ;;
      Stub) stub=$((stub + 1)) ;;
      *) unclass=$((unclass + 1)) ;;
    esac
  done <<< "${our_syms}"

  echo "  \"summary\": {"
  echo "    \"Implemented\": ${impl},"
  echo "    \"RawSyscall\": ${raw},"
  echo "    \"GlibcCallThrough\": ${glibc},"
  echo "    \"Stub\": ${stub},"
  echo "    \"Unclassified\": ${unclass}"
  echo "  }"
  echo "}"
} > "${MATRIX_OUT}"

if [[ $JSON_ONLY -eq 1 ]]; then
  echo "${MATRIX_OUT}"
  exit 0
fi

# ------------------------------------------------------------------
# Human-readable report
# ------------------------------------------------------------------
echo "=== ABI Symbol Audit ==="
echo "Library: ${OUR_LIB}"
echo "Total exported symbols: ${our_count}"
echo ""

# Count by status
impl=0; raw=0; glibc=0; stub=0; unclass=0
while IFS= read -r sym; do
  [[ -z "$sym" ]] && continue
  case "${SYM_STATUS[$sym]:-Unclassified}" in
    Implemented) impl=$((impl + 1)) ;;
    RawSyscall) raw=$((raw + 1)) ;;
    GlibcCallThrough) glibc=$((glibc + 1)) ;;
    Stub) stub=$((stub + 1)) ;;
    *) unclass=$((unclass + 1)) ;;
  esac
done <<< "${our_syms}"

echo "Classification:"
printf "  %-20s %d\n" "Implemented:" "$impl"
printf "  %-20s %d\n" "RawSyscall:" "$raw"
printf "  %-20s %d\n" "GlibcCallThrough:" "$glibc"
printf "  %-20s %d\n" "Stub:" "$stub"
printf "  %-20s %d\n" "Unclassified:" "$unclass"
echo ""

# List unclassified symbols if any
if [[ $unclass -gt 0 ]]; then
  echo "=== UNCLASSIFIED SYMBOLS ==="
  while IFS= read -r sym; do
    [[ -z "$sym" ]] && continue
    if [[ "${SYM_STATUS[$sym]:-Unclassified}" == "Unclassified" ]]; then
      echo "  $sym"
    fi
  done <<< "${our_syms}"
  echo ""
fi

# Host comparison
if [[ -f "${HOST_LIB}" ]]; then
  host_syms=$(nm -D --defined-only "${HOST_LIB}" 2>/dev/null | awk '$2 ~ /[TtWw]/ {gsub(/@.*/, "", $NF); print $NF}' | sort -u)
  host_count=$(echo "${host_syms}" | wc -w)
  our_clean=$(echo "${our_syms}" | sort -u)
  common=$(comm -12 <(echo "${our_clean}") <(echo "${host_syms}") | wc -l)
  echo "Host libc symbols: ${host_count}"
  echo "Common with host: ${common}"
  echo "Coverage: ${common}/${host_count}"
fi

echo ""
echo "Matrix written to: ${MATRIX_OUT}"
echo ""
echo "abi_audit: PASS"
