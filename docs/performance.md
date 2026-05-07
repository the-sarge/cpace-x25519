# Performance Benchmarks

Status: local measurement facade for release-readiness investigation. Benchmark
results are not release gates and should be compared across the same host,
toolchain, and benchmark command.

## Command

Use the Taskfile benchmark target so allocation metrics are always included:

```sh
task bench
```

Useful variants:

```sh
task bench BENCH='BenchmarkRoundTrip' BENCHTIME=5s BENCHCOUNT=5
task bench BENCH='BenchmarkSessionExport' BENCHTIME=3s BENCHCOUNT=5
task bench BENCH='BenchmarkDecodeMessage' BENCHTIME=3s BENCHCOUNT=5
```

The target expands to:

```sh
go test -run '^$' -bench "$BENCH" -benchmem -benchtime "$BENCHTIME" -count "$BENCHCOUNT" ./...
```

## Coverage

Current benchmark coverage includes:

- full initiator-responder round trip;
- `Start`;
- `Respond`;
- `Initiator.Finish`;
- `Responder.Finish`;
- `Session.Export` for 32-byte, 64-byte, and 1024-byte outputs;
- message A/B/C encoding;
- message A/B/C decoding.

The benchmarks use package-internal deterministic scalar readers so benchmark
numbers focus on CPace computation and allocation behavior rather than operating
system entropy latency.

## Evidence Guidance

For release notes or reviewer packets, record:

- commit SHA and dirty/clean state;
- Go version;
- host CPU and operating system;
- exact benchmark command;
- `ns/op`, `B/op`, and `allocs/op`;
- whether protocol, parser/framing, exporter, dependency, or toolchain changes
  landed since the prior benchmark baseline.
