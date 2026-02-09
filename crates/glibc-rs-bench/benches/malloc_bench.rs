//! Allocator benchmarks.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

fn bench_alloc_free_cycle(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096, 32768];
    let mut group = c.benchmark_group("alloc_free_cycle");

    for &size in sizes {
        group.bench_with_input(BenchmarkId::new("system", size), &size, |b, &sz| {
            b.iter(|| {
                let v = vec![0u8; sz];
                criterion::black_box(v);
            });
        });
    }
    group.finish();
}

fn bench_alloc_burst(c: &mut Criterion) {
    let mut group = c.benchmark_group("alloc_burst");

    group.bench_function("1000x64B", |b| {
        b.iter(|| {
            let allocs: Vec<Vec<u8>> = (0..1000).map(|_| vec![0u8; 64]).collect();
            criterion::black_box(allocs);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_alloc_free_cycle, bench_alloc_burst);
criterion_main!(benches);
