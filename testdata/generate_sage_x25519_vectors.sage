#!/usr/bin/env sage
import hashlib
import hmac
import json

import sage.env
from sage.all import GF

# Maintainers: fixture provenance, including the pinned Docker/Sage command and
# manual drift check, is emitted in document["meta"] below. Regeneration is
# intentionally manual; Docker/Sage is not required in normal PR CI.

P = 2^255 - 19
F = GF(P)
MASK_255 = (1 << 255) - 1

POINT_SIZE = 32
SCALAR_SIZE = 32
SHA512_BLOCK_SIZE = 128

A = F(486662)
HALF_A = F(243331)
TWO = F(2)
ONE = F(1)
ZERO = F(0)

DSI_X25519 = b"CPace255"
DSI_ISK = b"CPace255_ISK"
DRAFT_VERSION = b"draft-irtf-cfrg-cpace-21"
SUITE_NAME = b"CPACE-X25519-SHA512"
WIRE_FORMAT_V1 = 0xC1
WIRE_SUITE = 0x02
ROLE_A = 0x01
ROLE_B = 0x02
ROLE_C = 0x03

# Re-pinning this container requires regenerating sage-x25519-extended.json and
# updating sageX25519ExtendedJSONSHA256 plus the digest expectation in
# sage_vectors_test.go.
CONTAINER_DIGEST = "sagemath/sagemath@sha256:e068670ae5863b54b2550e72437ec637b0283acb0dc712c8584c124dbf44e667"
CONTAINER_IMAGE = CONTAINER_DIGEST
GENERATION_COMMAND = (
    "docker run --rm --platform linux/amd64 "
    "-v \"$PWD:/work\" -w /work "
    f"{CONTAINER_DIGEST} "
    "\"sage testdata/generate_sage_x25519_vectors.sage\" "
    "> testdata/sage-x25519-extended.json && "
    "rm -f testdata/generate_sage_x25519_vectors.sage.py"
)


def hx(data):
    return data.hex().upper()


def unhex(text):
    return bytes.fromhex(text)


def sha512(data):
    return hashlib.sha512(data).digest()


def leb128(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        out.append(b)
        if not n:
            return bytes(out)


def lv(data):
    return leb128(len(data)) + data


def lv_cat(*parts):
    return b"".join(lv(part) for part in parts)


def fe_from_bytes(encoded):
    if len(encoded) != POINT_SIZE:
        raise ValueError("field element encodings must be 32 bytes")
    return F(int.from_bytes(encoded, "little") & MASK_255)


def fe_bytes(x):
    return int(F(x)).to_bytes(POINT_SIZE, "little")


def clamp_scalar(scalar):
    if len(scalar) != SCALAR_SIZE:
        raise ValueError("scalar encodings must be 32 bytes")
    out = bytearray(scalar)
    out[0] &= 248
    out[31] &= 127
    out[31] |= 64
    return bytes(out)


def generator_string(dsi, prs, ci, sid, s_in_bytes):
    raw_zpad_len = s_in_bytes - len(lv(prs)) - len(lv(dsi)) - 1
    zpad_len = max(raw_zpad_len, 0)
    return lv_cat(dsi, prs, bytes(zpad_len), ci, sid)


def elligator2_curve25519(encoded_r):
    r = fe_from_bytes(encoded_r)
    v = -A / (ONE + TWO * r^2)
    rhs = v^3 + A * v^2 + v
    if rhs == ZERO:
        x = -HALF_A
    elif rhs.is_square():
        x = v
    else:
        x = -v - A
    return fe_bytes(x)


def calculate_generator(prs, ci, sid):
    gen = generator_string(DSI_X25519, prs, ci, sid, SHA512_BLOCK_SIZE)
    hashed = sha512(gen)[:POINT_SIZE]
    return gen, hashed, elligator2_curve25519(hashed)


def x25519(scalar, point):
    k = int.from_bytes(clamp_scalar(scalar), "little")
    x1 = fe_from_bytes(point)
    x2 = ONE
    z2 = ZERO
    x3 = x1
    z3 = ONE
    swap = 0

    for pos in range(254, -1, -1):
        bit = (k >> pos) & 1
        do_swap = int(swap != bit)
        if do_swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit

        d = x3 - z3
        b = x2 - z2
        a = x2 + z2
        c = x3 + z3
        da = d * a
        cb = c * b
        bb = b^2
        aa = a^2
        x3 = (da + cb)^2
        z3 = x1 * (da - cb)^2
        x2 = aa * bb
        e = aa - bb
        z2 = e * (bb + F(121666) * e)

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2

    if z2 == ZERO:
        return bytes(POINT_SIZE)
    return fe_bytes(x2 / z2)


def scalar_mult_vfy(scalar, point):
    out = x25519(scalar, point)
    return None if out == bytes(POINT_SIZE) else out


def assert_known_answers():
    scalar = unhex("A546E36BF0527C9D3B16154B82465EDD62144C0AC1FC5A18506A2244BA449AC4")
    point = unhex("E6DB6867583030DB3594C1A424B15F7C726624EC26B3353B10A903A6D0AB1C4C")
    want = unhex("C3DA55379DE9C6908E94EA4DF28D084F32ECCF03491C71F754B4075577A28552")
    got = x25519(scalar, point)
    if got != want:
        raise ValueError("RFC 7748 X25519 self-check failed: got %s want %s" % (hx(got), hx(want)))


def curve_rhs(u):
    x = fe_from_bytes(u)
    return x^3 + A * x^2 + x


def point_kind(point):
    value = int.from_bytes(point, "little")
    decoded = fe_from_bytes(point)
    rhs = curve_rhs(point)
    labels = []
    if value >= int(P):
        labels.append("non-canonical")
    if value >= (1 << 255):
        labels.append("high-bit-masked")
    if x25519(bytes([1]) + bytes(31), point) == bytes(POINT_SIZE):
        labels.append("low-order")
    labels.append("curve" if rhs == ZERO or rhs.is_square() else "twist")
    labels.append("u=" + str(int(decoded)))
    return labels


def deterministic_bytes(label, size):
    out = bytearray()
    counter = 0
    while len(out) < size:
        out.extend(sha512(label.encode("ascii") + counter.to_bytes(4, "little")))
        counter += 1
    return bytes(out[:size])


def find_point(label, want_curve):
    counter = 0
    while True:
        candidate = deterministic_bytes("%s-%d" % (label, counter), POINT_SIZE)
        if x25519(bytes([1]) + bytes(31), candidate) == bytes(POINT_SIZE):
            counter += 1
            continue
        rhs = curve_rhs(candidate)
        is_curve = rhs == ZERO or rhs.is_square()
        if is_curve == want_curve:
            return candidate
        counter += 1


def build_ci(initiator_id, responder_id, context):
    return lv_cat(
        b"CPace-Go-CI",
        DRAFT_VERSION,
        SUITE_NAME,
        b"initiator",
        initiator_id,
        b"responder",
        responder_id,
        b"context",
        context,
    )


def ir_transcript(ya, ada, yb, adb):
    return lv_cat(ya, ada) + lv_cat(yb, adb)


def transcript_id(transcript):
    return sha512(b"CPaceSidOutput" + transcript)


def derive_isk(sid, k, transcript):
    return sha512(lv_cat(DSI_ISK, sid, k) + transcript)


def confirmation_tag(isk, sid, y, ad):
    key = sha512(b"CPaceMac" + sid + isk)
    return hmac.new(key, lv_cat(y, ad), hashlib.sha512).digest()


def encode_message(role, *fields):
    return bytes([WIRE_FORMAT_V1, WIRE_SUITE, role]) + lv_cat(*fields)


def generator_case(name, prs, ci, sid, extra=None):
    gen, hashed, encoded = calculate_generator(prs, ci, sid)
    out = {
        "name": name,
        "prs": hx(prs),
        "ci": hx(ci),
        "sid": hx(sid),
        "h": "SHA-512",
        "h_s_in_bytes": SHA512_BLOCK_SIZE,
        "zpad_length": max(SHA512_BLOCK_SIZE - len(lv(prs)) - len(lv(DSI_X25519)) - 1, 0),
        "generator_string": hx(gen),
        "hash_to_field": hx(hashed),
        "decoded_field_element": hx(fe_bytes(fe_from_bytes(hashed))),
        "encoded_generator": hx(encoded),
    }
    if extra:
        out.update(extra)
    return out


def scalar_case(name, scalar, point, note):
    shared = x25519(scalar, point)
    vfy = scalar_mult_vfy(scalar, point)
    return {
        "name": name,
        "note": note,
        "scalar": hx(scalar),
        "clamped_scalar": hx(clamp_scalar(scalar)),
        "point": hx(point),
        "decoded_u": hx(fe_bytes(fe_from_bytes(point))),
        "point_kind": point_kind(point),
        "shared": hx(shared),
        "vfy_ok": vfy is not None,
    }


def exchange_case(name, password, initiator_id, responder_id, context, sid, ada, adb, ya_scalar, yb_scalar):
    ci = build_ci(initiator_id, responder_id, context)
    gen_string, hashed, g = calculate_generator(password, ci, sid)
    ya = x25519(ya_scalar, g)
    yb = x25519(yb_scalar, g)
    k_a = scalar_mult_vfy(ya_scalar, yb)
    k_b = scalar_mult_vfy(yb_scalar, ya)
    if k_a is None or k_b is None or k_a != k_b:
        raise ValueError("exchange scalar multiplication did not agree")
    transcript = ir_transcript(ya, ada, yb, adb)
    isk = derive_isk(sid, k_a, transcript)
    tag_a = confirmation_tag(isk, sid, ya, ada)
    tag_b = confirmation_tag(isk, sid, yb, adb)
    return {
        "name": name,
        "password": hx(password),
        "initiator_id": hx(initiator_id),
        "responder_id": hx(responder_id),
        "context": hx(context),
        "ci": hx(ci),
        "sid": hx(sid),
        "initiator_ad": hx(ada),
        "responder_ad": hx(adb),
        "initiator_scalar": hx(ya_scalar),
        "responder_scalar": hx(yb_scalar),
        "generator_string": hx(gen_string),
        "hash_to_field": hx(hashed),
        "generator": hx(g),
        "ya": hx(ya),
        "yb": hx(yb),
        "k": hx(k_a),
        "transcript_ir": hx(transcript),
        "isk_ir": hx(isk),
        "tag_a": hx(tag_a),
        "tag_b": hx(tag_b),
        "sid_output_ir": hx(transcript_id(transcript)),
        "message_a": hx(encode_message(ROLE_A, sid, ya, ada)),
        "message_b": hx(encode_message(ROLE_B, yb, adb, tag_b)),
        "message_c": hx(encode_message(ROLE_C, tag_a)),
    }


draft_prs = b"Password"
draft_ci = lv(b"A_initiator") + lv(b"B_responder")
draft_sid = unhex("7E4B4791D6A8EF019B936C79FB7F2C57")

package_password = b"correct horse battery staple"
package_initiator_id = b"alice@example"
package_responder_id = b"bob@example"
package_context = b"cpace-x25519 sage extended vectors"
package_sid = unhex("00112233445566778899AABBCCDDEEFF1021324354657687")
package_ci = build_ci(package_initiator_id, package_responder_id, package_context)

low_order_points = {
    "low-order-u0": bytes(POINT_SIZE),
    "low-order-u1": bytes([1]) + bytes(31),
    "low-order-p-minus-1": (int(P) - 1).to_bytes(POINT_SIZE, "little"),
    "low-order-p": int(P).to_bytes(POINT_SIZE, "little"),
}

noncanonical_points = {
    "noncanonical-p-plus-1": (int(P) + 1).to_bytes(POINT_SIZE, "little"),
    "noncanonical-2^255-minus-1": ((1 << 255) - 1).to_bytes(POINT_SIZE, "little"),
    "high-bit-basepoint": (9 + (1 << 255)).to_bytes(POINT_SIZE, "little"),
    "high-bit-zero": (1 << 255).to_bytes(POINT_SIZE, "little"),
}

scalar_random_0 = deterministic_bytes("cpace-x25519 sage scalar 0", SCALAR_SIZE)
scalar_random_1 = deterministic_bytes("cpace-x25519 sage scalar 1", SCALAR_SIZE)
scalar_adversarial = unhex("A546E36BF0527C9D3B16154B82465EDD62144C0AC1FC5A18506A2244BA449AC4")

assert_known_answers()

curve_point_0 = find_point("cpace-x25519 sage curve point", True)
twist_point_0 = find_point("cpace-x25519 sage twist point", False)

scalar_cases = [
    scalar_case("random-curve-0", scalar_random_0, curve_point_0, "deterministic SHA-512 scalar with a Sage-selected curve u-coordinate"),
    scalar_case("random-twist-0", scalar_random_1, twist_point_0, "deterministic SHA-512 scalar with a Sage-selected quadratic-twist u-coordinate"),
    scalar_case("basepoint-rfc-scalar", scalar_adversarial, bytes([9]) + bytes(31), "RFC 7748 scalar against the canonical X25519 basepoint"),
]

for case_name, point in sorted(low_order_points.items()):
    scalar_cases.append(scalar_case(case_name, scalar_adversarial, point, "adversarial low-order or identity-class u-coordinate"))

for case_name, point in sorted(noncanonical_points.items()):
    scalar_cases.append(scalar_case(case_name, scalar_random_0, point, "non-canonical or high-bit-masked u-coordinate accepted by RFC 7748 decoding"))

exchange_cases = [
    exchange_case(
        "package-profile-ascii",
        package_password,
        package_initiator_id,
        package_responder_id,
        package_context,
        package_sid,
        b"initiator associated data",
        b"responder associated data",
        deterministic_bytes("cpace-x25519 sage initiator scalar 0", SCALAR_SIZE),
        deterministic_bytes("cpace-x25519 sage responder scalar 0", SCALAR_SIZE),
    ),
    exchange_case(
        "package-profile-binary-context",
        unhex("00010203FEFF70617373776F7264"),
        unhex("A001696E69746961746F72FF"),
        unhex("B002726573706F6E64657200"),
        bytes(range(32)),
        unhex("F0E1D2C3B4A5968778695A4B3C2D1E0F"),
        bytes(16),
        bytes(reversed(range(16))),
        deterministic_bytes("cpace-x25519 sage initiator scalar 1", SCALAR_SIZE),
        deterministic_bytes("cpace-x25519 sage responder scalar 1", SCALAR_SIZE),
    ),
]

document = {
    "meta": {
        "name": "cpace-x25519 SageMath extended vector dataset",
        "schema": 1,
        "sage_version": sage.env.SAGE_VERSION,
        "container_image": CONTAINER_IMAGE,
        "container_digest": CONTAINER_DIGEST,
        "generation_script": "testdata/generate_sage_x25519_vectors.sage",
        "generation_command": GENERATION_COMMAND,
        "notes": [
            "The Sage script implements field arithmetic over GF(2^255-19), Elligator2 generator derivation, X25519 scalar multiplication, CPace transcript/ISK/tag derivation, and package message framing without importing Go code.",
            "Manual drift check: rerun the pinned generation_command, then run git diff --exit-code -- testdata/sage-x25519-extended.json; Docker/Sage is not required in normal PR CI.",
            "Scalar and point values labelled random are deterministic SHA-512 expansions so the generator is reproducible offline.",
            "Point decoding follows RFC 7748 by ignoring the top bit and accepting non-canonical encodings modulo 2^255-19.",
        ],
    },
    "generator_cases": [
        generator_case(
            "draft21-appendix-b-generator",
            draft_prs,
            draft_ci,
            draft_sid,
            {"source": "draft-irtf-cfrg-cpace-21 Appendix B.1.1.1 inputs"},
        ),
        generator_case(
            "package-profile-generator",
            package_password,
            package_ci,
            package_sid,
            {
                "initiator_id": hx(package_initiator_id),
                "responder_id": hx(package_responder_id),
                "context": hx(package_context),
                "source": "package-owned cpace-x25519 profile CI construction",
            },
        ),
    ],
    "scalar_mult_cases": scalar_cases,
    "exchange_cases": exchange_cases,
}

print(json.dumps(document, indent=2, sort_keys=True, default=int))
