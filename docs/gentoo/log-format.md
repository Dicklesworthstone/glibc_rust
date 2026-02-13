# FrankenLibC Gentoo Log Format

This document defines the JSONL schema accepted by:

- `scripts/gentoo/log_parser.py`
- `scripts/gentoo/log_validator.py`
- `scripts/gentoo/log_stats.py`

## Primary Runtime Schema

```json
{
  "ts": "2026-02-13T01:45:00.123456Z",
  "pid": 12345,
  "tid": 12346,
  "call": "malloc",
  "args": { "size": 4096 },
  "result": { "ptr": "0x7f1234567890", "actual_size": 4096 },
  "action": "ClampSize",
  "action_details": {
    "original_size": 8589934592,
    "clamped_size": 4096,
    "reason": "size_exceeds_max"
  },
  "latency_ns": 185,
  "stack_hash": "abc123def456"
}
```

Required:

- `ts` (or `timestamp`)
- `pid`
- `call` (or `event` for hook logs)
- `latency_ns` (`0` accepted for hook events)

## Hook Event Schema

Hook logs emitted by `frankenlibc-ebuild-hooks.sh` use:

```json
{
  "timestamp": "2026-02-13T01:45:00Z",
  "event": "enable",
  "atom": "sys-apps/coreutils-9.9-r1",
  "phase": "src_test",
  "pid": 4567,
  "message": "enabled"
}
```

Parser normalization:

- `event` -> `call="__hook_event__"`
- `event=enable|disable|skip` -> `action=hook_enable|hook_disable|hook_skip`

## Validation Rules

- Timestamp parseable as ISO8601.
- Latency in `[0, 1_000_000_000]` ns.
- Pointer fields under `result.ptr` must match `0x[0-9a-fA-F]+`.
- Healing actions should be one of known actions (`ClampSize`, `IgnoreDoubleFree`, etc.).
- Per-PID timestamps are checked for monotonic non-decreasing order.
