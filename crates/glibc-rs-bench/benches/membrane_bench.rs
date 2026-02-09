//! Membrane overhead benchmarks.
//!
//! Measures the per-call overhead of pointer validation at each
//! pipeline stage.

use criterion::{Criterion, criterion_group, criterion_main};
use glibc_rs_membrane::ptr_validator::ValidationPipeline;

fn bench_validate_null(c: &mut Criterion) {
    let pipeline = ValidationPipeline::new();
    c.bench_function("validate_null", |b| {
        b.iter(|| {
            criterion::black_box(pipeline.validate(0));
        });
    });
}

fn bench_validate_foreign(c: &mut Criterion) {
    let pipeline = ValidationPipeline::new();
    c.bench_function("validate_foreign", |b| {
        b.iter(|| {
            criterion::black_box(pipeline.validate(0xDEAD_BEEF_0000));
        });
    });
}

fn bench_validate_known(c: &mut Criterion) {
    let pipeline = ValidationPipeline::new();
    let ptr = pipeline.arena.allocate(256).expect("alloc");
    let addr = ptr as usize;
    pipeline.register_allocation(addr, 256);

    c.bench_function("validate_known", |b| {
        b.iter(|| {
            criterion::black_box(pipeline.validate(addr));
        });
    });

    pipeline.arena.free(ptr);
}

criterion_group!(
    benches,
    bench_validate_null,
    bench_validate_foreign,
    bench_validate_known
);
criterion_main!(benches);
