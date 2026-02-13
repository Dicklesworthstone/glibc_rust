use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use frankenlibc_core::errno;
use frankenlibc_core::pthread::mutex::{
    MutexContractOp, MutexContractState, PTHREAD_MUTEX_ERRORCHECK, PTHREAD_MUTEX_NORMAL,
    PTHREAD_MUTEX_RECURSIVE, mutex_contract_transition,
};

#[derive(Clone, Copy)]
struct Case {
    kind: i32,
    old_state: MutexContractState,
    op: MutexContractOp,
    expected_state: MutexContractState,
    expected_errno: i32,
    expected_blocks: bool,
}

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().parent().unwrap().to_path_buf()
}

fn state_name(state: MutexContractState) -> &'static str {
    match state {
        MutexContractState::Uninitialized => "Uninitialized",
        MutexContractState::Unlocked => "Unlocked",
        MutexContractState::LockedBySelf => "LockedBySelf",
        MutexContractState::LockedByOther => "LockedByOther",
        MutexContractState::Destroyed => "Destroyed",
    }
}

fn op_name(op: MutexContractOp) -> &'static str {
    match op {
        MutexContractOp::Init => "Init",
        MutexContractOp::Lock => "Lock",
        MutexContractOp::TryLock => "TryLock",
        MutexContractOp::Unlock => "Unlock",
        MutexContractOp::Destroy => "Destroy",
    }
}

fn kind_name(kind: i32) -> &'static str {
    match kind {
        PTHREAD_MUTEX_NORMAL => "NORMAL",
        PTHREAD_MUTEX_ERRORCHECK => "ERRORCHECK",
        PTHREAD_MUTEX_RECURSIVE => "RECURSIVE",
        _ => "UNKNOWN",
    }
}

fn matrix_cases() -> Vec<Case> {
    vec![
        Case {
            kind: PTHREAD_MUTEX_NORMAL,
            old_state: MutexContractState::Uninitialized,
            op: MutexContractOp::Init,
            expected_state: MutexContractState::Unlocked,
            expected_errno: 0,
            expected_blocks: false,
        },
        Case {
            kind: PTHREAD_MUTEX_NORMAL,
            old_state: MutexContractState::Unlocked,
            op: MutexContractOp::Lock,
            expected_state: MutexContractState::LockedBySelf,
            expected_errno: 0,
            expected_blocks: false,
        },
        Case {
            kind: PTHREAD_MUTEX_NORMAL,
            old_state: MutexContractState::LockedBySelf,
            op: MutexContractOp::Lock,
            expected_state: MutexContractState::LockedBySelf,
            expected_errno: 0,
            expected_blocks: true,
        },
        Case {
            kind: PTHREAD_MUTEX_ERRORCHECK,
            old_state: MutexContractState::LockedBySelf,
            op: MutexContractOp::Lock,
            expected_state: MutexContractState::LockedBySelf,
            expected_errno: errno::EDEADLK,
            expected_blocks: false,
        },
        Case {
            kind: PTHREAD_MUTEX_RECURSIVE,
            old_state: MutexContractState::LockedBySelf,
            op: MutexContractOp::Lock,
            expected_state: MutexContractState::LockedBySelf,
            expected_errno: 0,
            expected_blocks: false,
        },
        Case {
            kind: PTHREAD_MUTEX_NORMAL,
            old_state: MutexContractState::LockedByOther,
            op: MutexContractOp::TryLock,
            expected_state: MutexContractState::LockedByOther,
            expected_errno: errno::EBUSY,
            expected_blocks: false,
        },
        Case {
            kind: PTHREAD_MUTEX_NORMAL,
            old_state: MutexContractState::LockedByOther,
            op: MutexContractOp::Unlock,
            expected_state: MutexContractState::LockedByOther,
            expected_errno: errno::EPERM,
            expected_blocks: false,
        },
        Case {
            kind: PTHREAD_MUTEX_NORMAL,
            old_state: MutexContractState::LockedByOther,
            op: MutexContractOp::Destroy,
            expected_state: MutexContractState::LockedByOther,
            expected_errno: errno::EBUSY,
            expected_blocks: false,
        },
    ]
}

#[test]
fn contract_matrix_matches_expected_and_emits_structured_logs() {
    let root = workspace_root();
    let out_dir = root.join("target/conformance");
    fs::create_dir_all(&out_dir).expect("create target/conformance");

    let log_path = out_dir.join("pthread_mutex_contract_matrix.log.jsonl");
    let report_path = out_dir.join("pthread_mutex_contract_matrix.report.json");

    let mut log_lines = Vec::new();
    let mut mismatches = Vec::new();
    let mut total = 0usize;
    let mut passed = 0usize;

    for mode in ["strict", "hardened"] {
        for case in matrix_cases() {
            total += 1;
            let t0 = Instant::now();
            let got = mutex_contract_transition(case.kind, case.old_state, case.op);
            let timing_ns = t0.elapsed().as_nanos();

            let ok = got.next == case.expected_state
                && got.errno == case.expected_errno
                && got.blocks == case.expected_blocks;
            if ok {
                passed += 1;
            } else {
                mismatches.push(format!(
                    "{}:{}:{} expected(next={}, errno={}, blocks={}) got(next={}, errno={}, blocks={})",
                    mode,
                    kind_name(case.kind),
                    op_name(case.op),
                    state_name(case.expected_state),
                    case.expected_errno,
                    case.expected_blocks,
                    state_name(got.next),
                    got.errno,
                    got.blocks
                ));
            }

            let trace_id = format!(
                "pthread-mutex-contract:{}:{}:{}:{}",
                mode,
                kind_name(case.kind),
                state_name(case.old_state),
                op_name(case.op)
            );
            let status = if ok { "ok" } else { "mismatch" };
            log_lines.push(format!(
                "{{\"trace_id\":\"{}\",\"mode\":\"{}\",\"operation\":\"{}\",\"old_state\":\"{}\",\"new_state\":\"{}\",\"errno\":{},\"blocks\":{},\"timing_ns\":{},\"status\":\"{}\"}}",
                trace_id,
                mode,
                op_name(case.op),
                state_name(case.old_state),
                state_name(got.next),
                got.errno,
                got.blocks,
                timing_ns,
                status
            ));
        }
    }

    fs::write(&log_path, format!("{}\n", log_lines.join("\n"))).expect("write jsonl log");

    let report = format!(
        concat!(
            "{{\n",
            "  \"ok\": {},\n",
            "  \"total_cases\": {},\n",
            "  \"passed_cases\": {},\n",
            "  \"failed_cases\": {},\n",
            "  \"log_jsonl\": \"{}\",\n",
            "  \"mismatches\": [\n{}\n  ]\n",
            "}}\n"
        ),
        mismatches.is_empty(),
        total,
        passed,
        total - passed,
        log_path
            .strip_prefix(&root)
            .unwrap_or(&log_path)
            .to_string_lossy(),
        mismatches
            .iter()
            .map(|m| format!("    \"{}\"", m.replace('"', "\\\"")))
            .collect::<Vec<_>>()
            .join(",\n")
    );
    fs::write(&report_path, report).expect("write report json");

    assert!(
        mismatches.is_empty(),
        "contract matrix mismatch(es): {:?}",
        mismatches
    );
}
