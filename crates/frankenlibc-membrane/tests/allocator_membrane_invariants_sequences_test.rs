use frankenlibc_membrane::{SafetyState, ValidationOutcome, ValidationPipeline};
use serde_json::json;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn gen_range_usize(&mut self, low: usize, high_inclusive: usize) -> usize {
        assert!(low <= high_inclusive);
        let span = high_inclusive - low + 1;
        low + (self.next_u64() as usize % span)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotState {
    Empty,
    Live,
    Freed,
}

#[test]
fn deterministic_allocator_membrane_sequences_hold_core_invariants() {
    // Deterministic, bounded, and intentionally simple: this is invariant pressure,
    // not a fuzz campaign (those live in frankenlibc-fuzz).
    const SEEDS: [u64; 4] = [1, 2, 3, 4];
    const STEPS: usize = 2_000;
    const SLOTS: usize = 32;

    for seed in SEEDS {
        let pipeline = ValidationPipeline::new();
        let mut rng = XorShift64::new(seed);

        let mut ptrs = [std::ptr::null_mut::<u8>(); SLOTS];
        let mut sizes = [0_usize; SLOTS];
        let mut states = [SlotState::Empty; SLOTS];

        // Foreign pointers should remain allowed but Unknown/unbounded.
        let foreign_addr = 0xDEAD_BEEF_usize;
        let foreign_outcome = pipeline.validate(foreign_addr);
        assert!(
            matches!(foreign_outcome, ValidationOutcome::Foreign(_)),
            "seed={seed}: expected Foreign for foreign_addr"
        );
        assert!(foreign_outcome.can_read(), "seed={seed}: foreign can_read");
        assert!(
            foreign_outcome.can_write(),
            "seed={seed}: foreign can_write"
        );
        let foreign_abs = foreign_outcome.abstraction().expect("foreign abstraction");
        assert_eq!(
            foreign_abs.state,
            SafetyState::Unknown,
            "seed={seed}: foreign abstraction must be Unknown"
        );
        assert!(
            foreign_abs.remaining.is_none(),
            "seed={seed}: foreign abstraction must not claim bounds"
        );

        for step in 0..STEPS {
            let op = rng.gen_range_usize(0, 99);
            let idx = rng.gen_range_usize(0, SLOTS - 1);

            match op {
                // allocate (biased)
                0..=44 => {
                    if states[idx] != SlotState::Empty {
                        continue;
                    }
                    let size = rng.gen_range_usize(1, 2048);
                    let ptr = pipeline.allocate(size).expect("alloc");
                    ptrs[idx] = ptr;
                    sizes[idx] = size;
                    states[idx] = SlotState::Live;
                }
                // validate
                45..=84 => match states[idx] {
                    SlotState::Empty => {
                        let out = pipeline.validate(foreign_addr);
                        assert!(
                            matches!(out, ValidationOutcome::Foreign(_)),
                            "seed={seed} step={step}: foreign validate must be Foreign"
                        );
                    }
                    SlotState::Live => {
                        let addr = ptrs[idx] as usize;
                        let out = pipeline.validate(addr);
                        assert!(
                            matches!(
                                out,
                                ValidationOutcome::CachedValid(_) | ValidationOutcome::Validated(_)
                            ),
                            "seed={seed} step={step}: live validate must be CachedValid/Validated (got {out:?})"
                        );
                        assert!(
                            out.can_read() && out.can_write(),
                            "seed={seed} step={step}: live pointer must be readable+writable"
                        );
                        let abs = out.abstraction().expect("live abstraction");
                        assert_eq!(
                            abs.state,
                            SafetyState::Valid,
                            "seed={seed} step={step}: live abstraction must be Valid"
                        );
                        assert_eq!(
                            abs.remaining,
                            Some(sizes[idx]),
                            "seed={seed} step={step}: remaining must match allocation size"
                        );
                    }
                    SlotState::Freed => {
                        let addr = ptrs[idx] as usize;
                        let out = pipeline.validate(addr);
                        assert!(
                            matches!(out, ValidationOutcome::TemporalViolation(_)),
                            "seed={seed} step={step}: freed validate must be TemporalViolation (got {out:?})"
                        );
                        assert!(
                            !out.can_read() && !out.can_write(),
                            "seed={seed} step={step}: freed pointer must not be readable/writable"
                        );
                        assert!(
                            !matches!(out, ValidationOutcome::CachedValid(_)),
                            "seed={seed} step={step}: freed validate must never be CachedValid"
                        );
                    }
                },
                // free live
                85..=94 => {
                    if states[idx] != SlotState::Live {
                        continue;
                    }
                    let ptr = ptrs[idx];
                    let result = pipeline.free(ptr);
                    assert!(
                        matches!(result, frankenlibc_membrane::arena::FreeResult::Freed),
                        "seed={seed} step={step}: expected Freed on first free (got {result:?})"
                    );
                    states[idx] = SlotState::Freed;
                }
                // double-free attempt
                _ => {
                    if states[idx] != SlotState::Freed {
                        continue;
                    }
                    let ptr = ptrs[idx];
                    let result = pipeline.free(ptr);
                    assert!(
                        matches!(result, frankenlibc_membrane::arena::FreeResult::DoubleFree),
                        "seed={seed} step={step}: expected DoubleFree on second free (got {result:?})"
                    );
                }
            }
        }
    }
}

#[derive(Debug, Default)]
struct StressBatchResult {
    freed_or_absorbed: usize,
    double_free_detected: usize,
    unexpected: usize,
    attempts: usize,
    batch_elapsed_ns: u64,
}

#[derive(Debug, Clone)]
struct DoubleFreeStressReport {
    scenario: &'static str,
    mode: &'static str,
    allocations: usize,
    threads: usize,
    double_free_attempts: usize,
    detected_double_frees: usize,
    false_negatives: usize,
    false_positives: usize,
    first_pass_unexpected: usize,
    heap_integrity_failures: usize,
    mean_latency_ns: u64,
    p50_thread_latency_ns: u64,
    p95_thread_latency_ns: u64,
    max_thread_latency_ns: u64,
    uncontended_avg_latency_ns: u64,
    no_deadlock: bool,
}

fn percentile_ns(values: &[u64], pct: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let idx = ((sorted.len() - 1) * pct) / 100;
    sorted[idx]
}

fn current_mode_name() -> &'static str {
    use frankenlibc_membrane::config::{SafetyLevel, safety_level};
    match safety_level() {
        SafetyLevel::Off => "off",
        SafetyLevel::Strict => "strict",
        SafetyLevel::Hardened => "hardened",
    }
}

fn measure_uncontended_double_free_latency_ns(iterations: usize) -> u64 {
    assert!(iterations > 0);
    let pipeline = ValidationPipeline::new();
    let ptr = pipeline
        .allocate(64)
        .expect("allocation should succeed for latency probe");
    let first = pipeline.free(ptr);
    assert!(
        matches!(
            first,
            frankenlibc_membrane::arena::FreeResult::Freed
                | frankenlibc_membrane::arena::FreeResult::FreedWithCanaryCorruption
        ),
        "first free must succeed before double-free probe"
    );

    let t0 = Instant::now();
    let mut detected = 0usize;
    for _ in 0..iterations {
        if matches!(
            pipeline.free(ptr),
            frankenlibc_membrane::arena::FreeResult::DoubleFree
        ) {
            detected += 1;
        }
    }
    assert_eq!(detected, iterations, "all probe frees must be DoubleFree");
    (t0.elapsed().as_nanos() as u64 / iterations as u64).max(1)
}

fn run_double_free_stress(
    scenario: &'static str,
    allocations: usize,
    threads: usize,
    double_free_numer: usize,
    double_free_denom: usize,
) -> DoubleFreeStressReport {
    assert!(
        threads > 1,
        "threads must be > 1 for cross-thread double-free"
    );
    assert!(double_free_numer <= double_free_denom);
    assert!(double_free_denom > 0);

    let pipeline = Arc::new(ValidationPipeline::new());
    let mut ptrs = Vec::with_capacity(allocations);
    for i in 0..allocations {
        let size = 32 + (i % 96);
        let ptr = pipeline
            .allocate(size)
            .expect("allocation should succeed for stress setup");
        ptrs.push(ptr as usize);
    }

    let mut owner_batches: Vec<Vec<usize>> = (0..threads).map(|_| Vec::new()).collect();
    for (idx, ptr) in ptrs.iter().copied().enumerate() {
        owner_batches[idx % threads].push(ptr);
    }

    let mut second_batches: Vec<Vec<usize>> = (0..threads).map(|_| Vec::new()).collect();
    for (idx, ptr) in ptrs.iter().copied().enumerate() {
        if idx % double_free_denom < double_free_numer {
            let owner = idx % threads;
            let attacker = (owner + 1) % threads;
            second_batches[attacker].push(ptr);
        }
    }
    let double_free_attempts: usize = second_batches.iter().map(Vec::len).sum();

    let mut first_join = Vec::with_capacity(threads);
    for batch in owner_batches {
        let pipeline = Arc::clone(&pipeline);
        first_join.push(thread::spawn(move || {
            let mut out = StressBatchResult::default();
            for ptr in batch {
                match pipeline.free(ptr as *mut u8) {
                    frankenlibc_membrane::arena::FreeResult::Freed
                    | frankenlibc_membrane::arena::FreeResult::FreedWithCanaryCorruption => {
                        out.freed_or_absorbed += 1;
                    }
                    frankenlibc_membrane::arena::FreeResult::DoubleFree => {
                        out.double_free_detected += 1;
                    }
                    frankenlibc_membrane::arena::FreeResult::ForeignPointer
                    | frankenlibc_membrane::arena::FreeResult::InvalidPointer => {
                        out.unexpected += 1;
                    }
                }
            }
            out
        }));
    }

    let mut first = StressBatchResult::default();
    for handle in first_join {
        let part = handle
            .join()
            .expect("first-pass free thread must not panic");
        first.freed_or_absorbed += part.freed_or_absorbed;
        first.double_free_detected += part.double_free_detected;
        first.unexpected += part.unexpected;
    }

    let mut second_join = Vec::with_capacity(threads);
    for batch in second_batches {
        let pipeline = Arc::clone(&pipeline);
        second_join.push(thread::spawn(move || {
            let mut out = StressBatchResult::default();
            let t0 = Instant::now();
            out.attempts = batch.len();
            for ptr in batch {
                match pipeline.free(ptr as *mut u8) {
                    frankenlibc_membrane::arena::FreeResult::DoubleFree => {
                        out.double_free_detected += 1;
                    }
                    frankenlibc_membrane::arena::FreeResult::Freed
                    | frankenlibc_membrane::arena::FreeResult::FreedWithCanaryCorruption => {
                        out.freed_or_absorbed += 1;
                    }
                    frankenlibc_membrane::arena::FreeResult::ForeignPointer
                    | frankenlibc_membrane::arena::FreeResult::InvalidPointer => {
                        out.unexpected += 1;
                    }
                }
            }
            out.batch_elapsed_ns = t0.elapsed().as_nanos() as u64;
            out
        }));
    }

    let mut second = StressBatchResult::default();
    let mut thread_latencies = Vec::with_capacity(threads);
    for handle in second_join {
        let part = handle
            .join()
            .expect("second-pass double-free thread must not panic");
        second.freed_or_absorbed += part.freed_or_absorbed;
        second.double_free_detected += part.double_free_detected;
        second.unexpected += part.unexpected;
        second.attempts += part.attempts;
        second.batch_elapsed_ns = second
            .batch_elapsed_ns
            .saturating_add(part.batch_elapsed_ns);
        if part.attempts > 0 {
            thread_latencies.push(part.batch_elapsed_ns / part.attempts as u64);
        }
    }

    let false_negatives = double_free_attempts.saturating_sub(second.double_free_detected);
    let false_positives = first.double_free_detected;

    let mut heap_integrity_failures = 0usize;
    for ptr in &ptrs {
        let out = pipeline.validate(*ptr);
        if !matches!(out, ValidationOutcome::TemporalViolation(_)) {
            heap_integrity_failures += 1;
        }
    }

    let mean_latency_ns = if second.attempts == 0 {
        0
    } else {
        (second.batch_elapsed_ns / second.attempts as u64).max(1)
    };
    let uncontended_avg_latency_ns = measure_uncontended_double_free_latency_ns(20_000);

    DoubleFreeStressReport {
        scenario,
        mode: current_mode_name(),
        allocations,
        threads,
        double_free_attempts,
        detected_double_frees: second.double_free_detected,
        false_negatives,
        false_positives,
        first_pass_unexpected: first.unexpected,
        heap_integrity_failures,
        mean_latency_ns,
        p50_thread_latency_ns: percentile_ns(&thread_latencies, 50),
        p95_thread_latency_ns: percentile_ns(&thread_latencies, 95),
        max_thread_latency_ns: thread_latencies.iter().copied().max().unwrap_or(0),
        uncontended_avg_latency_ns,
        no_deadlock: true,
    }
}

#[test]
fn concurrent_double_free_detection_basic_10k_16t_10pct() {
    let report = run_double_free_stress("basic", 10_000, 16, 1, 10);

    assert_eq!(report.false_negatives, 0, "double-free false negatives");
    assert_eq!(report.false_positives, 0, "legitimate free false positives");
    assert_eq!(
        report.first_pass_unexpected, 0,
        "unexpected first-pass free outcomes"
    );
    assert_eq!(
        report.heap_integrity_failures, 0,
        "post-stress heap integrity failures"
    );
    assert!(report.no_deadlock, "stress threads must not deadlock");
    assert_eq!(
        report.detected_double_frees, report.double_free_attempts,
        "all second-pass double-free attempts must be detected"
    );

    let payload = json!({
        "scenario": report.scenario,
        "mode": report.mode,
        "allocations": report.allocations,
        "threads": report.threads,
        "double_free_attempts": report.double_free_attempts,
        "detected_double_frees": report.detected_double_frees,
        "false_negatives": report.false_negatives,
        "false_positives": report.false_positives,
        "first_pass_unexpected": report.first_pass_unexpected,
        "heap_integrity_failures": report.heap_integrity_failures,
        "mean_latency_ns": report.mean_latency_ns,
        "p50_thread_latency_ns": report.p50_thread_latency_ns,
        "p95_thread_latency_ns": report.p95_thread_latency_ns,
        "max_thread_latency_ns": report.max_thread_latency_ns,
        "uncontended_avg_latency_ns": report.uncontended_avg_latency_ns,
        "no_deadlock": report.no_deadlock
    });
    println!("DOUBLE_FREE_REPORT {}", payload);
}

#[test]
fn concurrent_double_free_detection_stress_100k_64t_50pct() {
    let report = run_double_free_stress("stress", 100_000, 64, 1, 2);

    assert_eq!(report.false_negatives, 0, "double-free false negatives");
    assert_eq!(report.false_positives, 0, "legitimate free false positives");
    assert_eq!(
        report.first_pass_unexpected, 0,
        "unexpected first-pass free outcomes"
    );
    assert_eq!(
        report.heap_integrity_failures, 0,
        "post-stress heap integrity failures"
    );
    assert!(report.no_deadlock, "stress threads must not deadlock");
    assert_eq!(
        report.detected_double_frees, report.double_free_attempts,
        "all second-pass double-free attempts must be detected"
    );
    assert!(
        report.double_free_attempts >= 50_000,
        "stress profile must exercise at least 50k second-free attempts"
    );

    let payload = json!({
        "scenario": report.scenario,
        "mode": report.mode,
        "allocations": report.allocations,
        "threads": report.threads,
        "double_free_attempts": report.double_free_attempts,
        "detected_double_frees": report.detected_double_frees,
        "false_negatives": report.false_negatives,
        "false_positives": report.false_positives,
        "first_pass_unexpected": report.first_pass_unexpected,
        "heap_integrity_failures": report.heap_integrity_failures,
        "mean_latency_ns": report.mean_latency_ns,
        "p50_thread_latency_ns": report.p50_thread_latency_ns,
        "p95_thread_latency_ns": report.p95_thread_latency_ns,
        "max_thread_latency_ns": report.max_thread_latency_ns,
        "uncontended_avg_latency_ns": report.uncontended_avg_latency_ns,
        "no_deadlock": report.no_deadlock
    });
    println!("DOUBLE_FREE_REPORT {}", payload);
}
