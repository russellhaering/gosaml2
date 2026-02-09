# Internal Fuzzing for gosaml2

This directory contains fuzzing targets for gosaml2 that are used with Go's built-in fuzzing functionality and OSS-Fuzz.

## Running Fuzzers Locally

```bash
go test -fuzz=FuzzDecodeResponse ./internal/fuzz/ -fuzztime=30s
go test -fuzz=FuzzLogoutResponse ./internal/fuzz/ -fuzztime=30s
go test -fuzz=FuzzBuildRequest ./internal/fuzz/ -fuzztime=30s
```

## OSS-Fuzz Integration

These fuzzers use native Go fuzzing (`func Fuzz(f *testing.F)`) and are compiled
by OSS-Fuzz using `compile_native_go_fuzzer`. Configuration files for the integration
can be found in the `oss-fuzz` directory.