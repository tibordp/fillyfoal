#!/bin/sh
# Writes two ONNX look-alike protobufs with protoc (see lookalike.proto):
# a person record and a client config. Run from this directory.
set -eu
out=../../fixtures/external/protobuf
printf 'id: 3\nname: "alice"\nemail: "alice@example.invalid"\n' |
    protoc --encode=demo.Person lookalike.proto > "$out/person.pb"
printf 'version: 1\nclient: "some-client"\nlimits { retries: 1 backoff: 2 }\n' |
    protoc --encode=demo.ClientConfig lookalike.proto > "$out/client-config.pb"
