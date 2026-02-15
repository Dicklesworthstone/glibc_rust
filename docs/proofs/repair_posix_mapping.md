# Hardened Repair/POSIX Mapping (bd-249m.2)

This table records the deterministic mapping from hardened invalid-input class to repair/deny action and POSIX-facing fixture outcome.

| Invalid Input Class | Family/Symbol | Decision | Healing Action | Expected Output (fixture) | Expected errno |
|---|---|---|---|---|---|
| `memcpy_overflow` | `StringMemory/memcpy` | Repair | `ClampSize` | `[1, 2]` | `0` |
| `unterminated_scan` | `StringMemory/strlen` | Repair | `ClampSize` | `3` | `0` |
| `string_copy_overflow` | `StringMemory/strcpy` | Repair | `TruncateWithNull` | `[65, 0]` | `0` |
| `string_concat_overflow` | `StringMemory/strcat` | Repair | `TruncateWithNull` | `[65, 66, 0]` | `0` |
| `wide_copy_overflow` | `WideChar/wcscpy` | Repair | `TruncateWithNull` | `[65, 0]` | `0` |
| `iconv_unsupported_encoding` | `Iconv/iconv_open` | Deny | `None` | `open_err errno=22` | `22` |
| `poll_oversized_nfds` | `Poll/poll` | Repair | `ClampSize` | `POLL_CLAMPED` | `0` |
| `locale_unsupported_fallback` | `Locale/setlocale` | Repair | `ReturnSafeDefault` | `C` | `0` |
| `mmap_invalid_protection` | `VirtualMemory/mmap` | Repair | `UpgradeToSafeVariant` | `MAPPED_REPAIRED` | `0` |
| `mmap_missing_visibility` | `VirtualMemory/mmap` | Repair | `UpgradeToSafeVariant` | `MAPPED_REPAIRED` | `0` |
| `startup_unterminated_auxv` | `Startup/__frankenlibc_startup_phase0` | Deny | `None` | `DENY_INVALID_STARTUP_CONTEXT` | `7` |
| `socket_invalid_domain` | `Socket/socket` | Deny | `None` | `-1` | `97` |
| `invalid_signal_number` | `Signal/kill` | Deny | `None` | `-1` | `22` |
| `invalid_resource_query` | `Resource/getrlimit` | Deny | `None` | `-1` | `22` |
| `invalid_terminal_fd` | `Termios/tcgetattr` | Deny | `None` | `-1` | `9` |

## Sources
- Matrix artifact: `tests/conformance/hardened_repair_deny_matrix.v1.json`
- Fixture references: `tests/conformance/fixtures/*.json` entries linked in matrix `fixture_case_refs`
- Gate enforcement: `scripts/check_hardened_repair_deny_matrix.sh`
