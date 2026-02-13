# Clean-Room Mutex Semantics Contract (bd-327)

This contract defines phase-scoped behavior for `pthread_mutex_*` without consulting legacy implementation internals.

## Scope

- Mutex kinds: `NORMAL`, `ERRORCHECK`, `RECURSIVE`
- Operations: `init`, `lock`, `trylock`, `unlock`, `destroy`
- Modes: strict/hardened share the same functional errno contract in this phase.
- Deferred features (explicit): process-shared, robust, PI/PP protocols.

## State Model

- `Uninitialized`
- `Unlocked`
- `LockedBySelf`
- `LockedByOther`
- `Destroyed`

The executable contract is implemented in `mutex_contract_transition` in `crates/frankenlibc-core/src/pthread/mutex.rs`.

## Transition Highlights

### `NORMAL`

- `Unlocked + lock -> LockedBySelf (0)`
- `LockedBySelf + lock -> blocks (deadlock risk; errno 0 at call boundary)`
- `LockedBySelf + trylock -> EBUSY`
- `LockedByOther + lock -> blocks`
- `LockedByOther + trylock -> EBUSY`
- `LockedByOther + unlock -> EPERM`
- `LockedBy* + destroy -> EBUSY`

### `ERRORCHECK`

- Same as `NORMAL` except:
  - `LockedBySelf + lock -> EDEADLK` (non-blocking failure)

### `RECURSIVE`

- Same as `NORMAL` except:
  - `LockedBySelf + lock -> success (stays LockedBySelf)`
  - `LockedBySelf + trylock -> success (stays LockedBySelf)`

## Attribute Handling Matrix

Current phase support is intentionally conservative:

- Supported:
  - default/private mutex attributes
- Deferred (deterministic `EINVAL`):
  - `process_shared`
  - `robust`
  - `priority_inherit`
  - `priority_protect`

Executable helpers:

- `mutex_attr_is_supported`
- `mutex_attr_support_errno`

## Errno Contract

- `EINVAL`: uninitialized/destroyed misuse, unsupported attributes, invalid kind
- `EBUSY`: `trylock` under contention, `destroy` while locked, re-init while initialized
- `EPERM`: unlock by non-owner/unlocked state
- `EDEADLK`: `ERRORCHECK` relock by owner
- `0`: success

## Contention/Fairness Notes

Futex path uses:

- uncontended CAS fast path
- bounded spin classification
- futex wait/wake parking

Wake ordering is kernel-scheduled (not strict FIFO), with wake-on-contended-unlock to reduce starvation risk.
