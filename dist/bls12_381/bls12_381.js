"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.to_pxpy = to_pxpy;
exports.hash_point_to_ge = hash_point_to_ge;
exports.hash_to_fe = hash_to_fe;
exports.generate_fe = generate_fe;
exports.generate_ge = generate_ge;
exports.ec_add = ec_add;
exports.ec_fe_mul = ec_fe_mul;
exports.ec_fe_sub = ec_fe_sub;
exports.ec_scalar_mul = ec_scalar_mul;
exports.NIZK_DLOG_generate_proof = NIZK_DLOG_generate_proof;
exports.NIZK_DLOG_verify_proof = NIZK_DLOG_verify_proof;
exports.genKeyImage = genKeyImage;
exports.create_ring_link = create_ring_link;
exports.getRandomShiftFactor = getRandomShiftFactor;
exports.createRing = createRing;
exports.generate_ring_signature = generate_ring_signature;
exports.verify_ring_signature = verify_ring_signature;
exports.construct_avm_ring_signature = construct_avm_ring_signature;
const bls12_381_1 = require("@noble/curves/bls12-381");
const sha3_1 = require("@noble/hashes/sha3");
const utils = __importStar(require("@noble/curves/abstract/utils"));
const CURVE_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
// The AVM represents points as their X and Y points concatenated
function to_pxpy(input) {
    const p = bls12_381_1.bls12_381.G1.ProjectivePoint.fromHex(utils.bytesToHex(input));
    return utils.concatBytes(utils.numberToBytesBE(p.x, 48), utils.numberToBytesBE(p.y, 48));
}
function hash_point_to_ge(input) {
    const pxpy = to_pxpy(input);
    const hash = sha3_1.keccak_256.create().update(pxpy).digest();
    const number = utils.hexToNumber(utils.bytesToHex(hash));
    //TODO: Need to look into implementing ExpandMsgXmd in AVM; and then call HashToCurve directly from Nobles
    return bls12_381_1.bls12_381.G1.ProjectivePoint.fromAffine(bls12_381_1.bls12_381.G1.mapToCurve([number]).toAffine()).toRawBytes();
}
function hash_to_fe(...args) {
    const hasher = sha3_1.keccak_256.create();
    for (let arg of args) {
        hasher.update(arg);
    }
    //TODO: Understand if this is introducing dangerous modulo bias
    return utils.numberToBytesBE(utils.hexToNumber(utils.bytesToHex(hasher.digest())) % CURVE_ORDER, 32);
}
function generate_fe() {
    return bls12_381_1.bls12_381.utils.randomPrivateKey();
}
function generate_ge(fe) {
    return bls12_381_1.bls12_381.getPublicKey(fe);
}
function ec_add(p1, p2) {
    return bls12_381_1.bls12_381.G1.ProjectivePoint.fromHex(utils.bytesToHex(p1)).add(bls12_381_1.bls12_381.G1.ProjectivePoint.fromHex(utils.bytesToHex(p2))).toRawBytes();
}
function ec_fe_mul(fe1, fe2) {
    return utils.numberToBytesBE(bls12_381_1.bls12_381.G1.normPrivateKeyToScalar(utils.bytesToNumberBE(fe1) * utils.bytesToNumberBE(fe2)), 32);
}
function ec_fe_sub(fe1, fe2) {
    return utils.numberToBytesBE(bls12_381_1.bls12_381.G1.normPrivateKeyToScalar(utils.bytesToNumberBE(fe1) - utils.bytesToNumberBE(fe2)), 32);
}
function ec_scalar_mul(p, scalar) {
    if (p === 1) {
        return bls12_381_1.bls12_381.G1.ProjectivePoint.fromPrivateKey(scalar).toRawBytes();
    }
    return bls12_381_1.bls12_381.G1.ProjectivePoint.fromHex(utils.bytesToHex(p)).multiply(utils.bytesToNumberBE(scalar)).toRawBytes();
}
/*
Non-Interactive Zero - Knowledge Proof of Discrete Logarithm Knowledge(DLOG)

Given x = g ^ a, prove knowledge of a without revealing it.

1: Prover samples a random r < - Z_q and computes v = g ^ r.
2: Challenge is calculated as hash(g, x, v).
3: Prover computes z = r - c * a.
4: Verifier accepts iff v == g ^ z * x ^ c.

Normally step 2 involves the verifier sampling c and sending it to the prover.
However, we use the Fiat - Shamir heuristic to turn this protocol NON - INTERACTIVE.

Since v = g ^ r, z = r - c * a and x = g ^ a, step 4 is
--> g ^ r == g ^ (r - c * a) * (g ^ a) ^ c == g ^ r * g ^ -ca * g ^ ac == g ^ r

*/
function NIZK_DLOG_generate_proof(a) {
    const x = generate_ge(a); // x = g ^a
    const x_hashable = to_pxpy(x);
    const r = generate_fe(); // r < - Z_q
    const v = generate_ge(r); // v = g ^ r
    const v_hashable = to_pxpy(v);
    const g_hashable = to_pxpy(bls12_381_1.bls12_381.G1.ProjectivePoint.BASE.toRawBytes());
    // Compute the challenge c
    const concatenated = utils.concatBytes(g_hashable, x_hashable, v_hashable);
    const challenge = utils.numberToBytesBE(utils.bytesToNumberBE(sha3_1.keccak_256.create().update(concatenated).digest()) % 52435875175126190479447740508185965837690552500527637822603658699938581184513n, 32);
    // The challenge can be between 0 and 2^256 - 1, but the scalar is between 1 and the curve order (approx 2^254.857089413)
    // TODO: Check if this biasing is acceptable, since everything over 52435875175126190479447740508185965837690552500527637822603658699938581184513
    // will loop over and we will get a bias towards lower numbers
    const z = ec_fe_sub(r, ec_fe_mul(challenge, a));
    // This is a very rare edge case where z is 0, which is not a valid scalar. The prover should retry in this case.
    // TODO: Decide on how to handle this better?
    if (z === new Uint8Array(32)) {
        throw new Error('error: z is 0, please re-run'); // Should be astronomically rare
    }
    return [g_hashable, x_hashable, v_hashable, z];
}
function NIZK_DLOG_verify_proof(g_bytes, x_bytes, v_bytes, z) {
    // Compute the challenge c
    const concatenated = utils.concatBytes(g_bytes, x_bytes, v_bytes);
    const challenge = utils.numberToBytesBE(utils.bytesToNumberBE(sha3_1.keccak_256.create().update(concatenated).digest()) % 52435875175126190479447740508185965837690552500527637822603658699938581184513n, 32);
    // The challenge can be between 0 and 2^256-1, but the scalar is between 0 and the curve order (approx 2^254.857089413)
    // TODO: Check if this biasing is acceptable, since everything over 52435875175126190479447740508185965837690552500527637822603658699938581184513
    // will loop over and we will get a bias towards lower numbers
    const v = bls12_381_1.bls12_381.G1.ProjectivePoint.fromHex(utils.bytesToHex(v_bytes)); // v_x sliced out
    const g = bls12_381_1.bls12_381.G1.ProjectivePoint.fromHex(utils.bytesToHex(g_bytes)).toRawBytes();
    const x = bls12_381_1.bls12_381.G1.ProjectivePoint.fromHex(utils.bytesToHex(x_bytes)).toRawBytes();
    const rhs = bls12_381_1.bls12_381.G1.ProjectivePoint.fromHex(utils.bytesToHex(ec_add(ec_scalar_mul(g, z), ec_scalar_mul(x, challenge))));
    return v.px === rhs.px && v.py === rhs.py && v.pz === rhs.pz;
}
function genKeyImage(sk, pk) {
    // Generates key image, either from the actual SK and PK of the signer, or from a random scalar and PK in the ring
    const keyImage = hash_point_to_ge(pk);
    return ec_scalar_mul(keyImage, sk);
}
function create_ring_link(msg, r, c, pk, key_image) {
    if ((c === 0) || (key_image === 0)) {
        return hash_to_fe(msg, ec_scalar_mul(1, r), genKeyImage(r, pk));
    }
    return hash_to_fe(msg, ec_add(ec_scalar_mul(1, r), ec_scalar_mul(pk, c)), ec_add(genKeyImage(r, pk), ec_scalar_mul(key_image, c)));
}
function areEqual(a, b) {
    return a.length === b.length && a.every((val, index) => val === b[index]);
}
function getRandomShiftFactor(n) {
    return Math.floor(Math.random() * n);
}
function createRing(n, signerIdx, signerPk) {
    let ring = [];
    for (let i = 0; i < n; i++) {
        if (i === signerIdx) {
            ring.push(signerPk);
        }
        else {
            ring.push(generate_ge(generate_fe()));
        }
    }
    return ring;
}
function generate_ring_signature(msg, sk, ring, keyImage) {
    const pi = ring.findIndex(pk => areEqual(pk, generate_ge(sk)));
    if (pi === -1) {
        throw new Error('error: signer not found in ring');
    }
    const n = ring.length;
    let nonces = [];
    for (let i = 0; i < n; i++) {
        nonces.push(generate_fe());
    }
    let values = [];
    for (let i = 0; i < n; i++) {
        const j = (i + pi) % n;
        const k = (i + pi + 1) % n;
        if (j === pi) {
            values[k] = create_ring_link(msg, nonces[j], 0, ring[j], 0);
        }
        else {
            values[k] = create_ring_link(msg, nonces[j], values[j], ring[j], keyImage);
        }
    }
    const r_pi = ec_fe_sub(nonces[pi], ec_fe_mul(values[pi], sk));
    nonces[pi] = r_pi;
    let signature = [];
    signature.push(values[0]);
    for (let i = 0; i < n; i++) {
        signature.push(nonces[i]);
    }
    if (!verify_ring_signature(msg, signature, ring, keyImage)) {
        throw new Error('error: generated ring signature not valid');
    }
    return { signature, keyImage };
}
function verify_ring_signature(msg, signature, ring, keyImage) {
    const n = ring.length;
    let values_prime = [];
    values_prime[0] = signature[0];
    for (let i = 0; i < n - 1; i++) {
        values_prime[i + 1] = create_ring_link(msg, signature[i + 1], values_prime[i], ring[i], keyImage);
    }
    values_prime[0] = create_ring_link(msg, signature[n], values_prime[n - 1], ring[n - 1], keyImage);
    return areEqual(values_prime[0], signature[0]);
}
// Prepare Ring Signature for AVM App+LSig Combo Consumption
function construct_avm_ring_signature(msg, signature, ring, keyImage) {
    const n = ring.length;
    let intermediateValues = [];
    intermediateValues.push(signature[0]);
    const signatureConcat = new Uint8Array(signature.length * 32);
    for (let i = 0; i < signature.length; i++) {
        signatureConcat.set(signature[i], i * 32);
    }
    for (let i = 0; i < n - 1; i++) {
        intermediateValues.push(create_ring_link(msg, signatureConcat.slice((i + 1) * 32, (i + 2) * 32), intermediateValues[i], ring[i], keyImage));
    }
    intermediateValues.push(create_ring_link(msg, signature[n], intermediateValues[n - 1], ring[n - 1], keyImage));
    if (!areEqual(intermediateValues[0], signature[0])) {
        throw new Error('error: ring signature not valid');
    }
    const intermediateValuesConcat = new Uint8Array(intermediateValues.flatMap(value => Array.from(value)));
    return { msg, signatureConcat, intermediateValues: intermediateValuesConcat };
}
