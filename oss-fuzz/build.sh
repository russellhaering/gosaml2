#!/bin/bash -eu
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

cd $SRC/gosaml2

# Build fuzzers
compile_native_go_fuzzer github.com/russellhaering/gosaml2/internal/fuzz FuzzDecodeResponse fuzz_decode_response
compile_native_go_fuzzer github.com/russellhaering/gosaml2/internal/fuzz FuzzLogoutResponse fuzz_logout_response
compile_native_go_fuzzer github.com/russellhaering/gosaml2/internal/fuzz FuzzBuildRequest fuzz_build_request

# Create seed corpus
mkdir -p $OUT/fuzz_decode_response_seed_corpus
# Use existing test data as seed corpus
find ./testdata -name '*.b64' -o -name '*.xml' | while read f; do
  cp "$f" $OUT/fuzz_decode_response_seed_corpus/
done
zip -j $OUT/fuzz_decode_response_seed_corpus.zip $OUT/fuzz_decode_response_seed_corpus/*
rm -rf $OUT/fuzz_decode_response_seed_corpus

# Create a minimal seed corpus for the logout response
mkdir -p $OUT/fuzz_logout_response_seed_corpus
# Find logout response files if they exist, otherwise use a subset of the general ones
find ./testdata -name '*logout*' -o -name '*.b64' | head -n 5 | while read f; do
  cp "$f" $OUT/fuzz_logout_response_seed_corpus/
done
zip -j $OUT/fuzz_logout_response_seed_corpus.zip $OUT/fuzz_logout_response_seed_corpus/*
rm -rf $OUT/fuzz_logout_response_seed_corpus

# Create a minimal seed corpus for build request
mkdir -p $OUT/fuzz_build_request_seed_corpus
echo "relayState" > $OUT/fuzz_build_request_seed_corpus/relaystate
echo "state123456" > $OUT/fuzz_build_request_seed_corpus/state
zip -j $OUT/fuzz_build_request_seed_corpus.zip $OUT/fuzz_build_request_seed_corpus/*
rm -rf $OUT/fuzz_build_request_seed_corpus
