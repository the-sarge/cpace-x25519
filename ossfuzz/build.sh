#!/bin/bash -eu
# Copyright 2026 Google LLC
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

src_dir="$SRC/cpace-x25519"
build_dir="$WORK/cpace-x25519-build"
rm -rf "$build_dir"
mkdir -p "$build_dir"
cp -a "$src_dir"/. "$build_dir"/
cd "$build_dir"

go install github.com/AdamKorcz/go-118-fuzz-build@latest
go get github.com/AdamKorcz/go-118-fuzz-build/testing

compile_native_go_fuzzer github.com/the-sarge/cpace-x25519 FuzzDecodeMessageA fuzz_decode_message_a
compile_native_go_fuzzer github.com/the-sarge/cpace-x25519 FuzzDecodeMessageB fuzz_decode_message_b
compile_native_go_fuzzer github.com/the-sarge/cpace-x25519 FuzzDecodeMessageC fuzz_decode_message_c
compile_native_go_fuzzer github.com/the-sarge/cpace-x25519 FuzzDraftVectorJSONLoader fuzz_draft_vector_json_loader
compile_native_go_fuzzer github.com/the-sarge/cpace-x25519 FuzzDraftInvalidVectorJSONLoader fuzz_draft_invalid_vector_json_loader
compile_native_go_fuzzer github.com/the-sarge/cpace-x25519 FuzzProtocolConsistency fuzz_protocol_consistency
compile_native_go_fuzzer github.com/the-sarge/cpace-x25519 FuzzProtocolMismatch fuzz_protocol_mismatch
compile_native_go_fuzzer github.com/the-sarge/cpace-x25519 FuzzRespondWithFuzzedMessageA fuzz_respond_with_fuzzed_message_a
compile_native_go_fuzzer github.com/the-sarge/cpace-x25519 FuzzInitiatorFinishWithFuzzedMessageB fuzz_initiator_finish_with_fuzzed_message_b
compile_native_go_fuzzer github.com/the-sarge/cpace-x25519 FuzzResponderFinishWithFuzzedMessageC fuzz_responder_finish_with_fuzzed_message_c
compile_native_go_fuzzer github.com/the-sarge/cpace-x25519 FuzzScalarMultVFY fuzz_scalar_mult_vfy
compile_native_go_fuzzer github.com/the-sarge/cpace-x25519 FuzzMessageARoundTrip fuzz_message_a_round_trip
compile_native_go_fuzzer github.com/the-sarge/cpace-x25519 FuzzMessageBRoundTrip fuzz_message_b_round_trip
compile_native_go_fuzzer github.com/the-sarge/cpace-x25519 FuzzMessageCRoundTrip fuzz_message_c_round_trip
