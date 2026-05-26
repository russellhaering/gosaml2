# OSS-Fuzz Integration for gosaml2

This directory contains the configuration files necessary for integrating gosaml2 with Google's [OSS-Fuzz](https://github.com/google/oss-fuzz) continuous fuzzing service.

## Files

- `build.sh`: Build script that compiles the fuzzing targets and creates the seed corpora
- `Dockerfile`: Defines the Docker container used for building the fuzzers
- `project.yaml`: Project configuration for OSS-Fuzz
- `fuzz_decode_response.options`: Fuzzer-specific options for the SAML response decoder

## Fuzzing Targets

The actual fuzzing targets are implemented in the `internal/fuzz` directory:

1. `FuzzDecodeResponse`: Fuzzes SAML response decoding and validation
2. `FuzzLogoutResponse`: Fuzzes SAML logout response decoding
3. `FuzzBuildRequest`: Fuzzes SAML authentication request building
4. `FuzzXMLValidation`: Fuzzes XML validation to catch parsing vulnerabilities

## Testing Locally with Docker

To test the OSS-Fuzz integration locally:

```bash
# Clone OSS-Fuzz
git clone https://github.com/google/oss-fuzz
cd oss-fuzz

# Build the image
python infra/helper.py build_image gosaml2

# Build the fuzzers
python infra/helper.py build_fuzzers gosaml2

# Run the fuzzers
python infra/helper.py run_fuzzer gosaml2 fuzz_decode_response
```

## Adding New Fuzzers

To add a new fuzzer:

1. Add the fuzzer implementation to `internal/fuzz/`
2. Update `build.sh` to compile the new fuzzer and create its seed corpus
3. Create fuzzer options file if needed (e.g., `my_new_fuzzer.options`) 