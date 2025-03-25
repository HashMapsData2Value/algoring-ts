import { bls12_381 } from '@noble/curves/bls12-381';
import { keccak_256 } from '@noble/hashes/sha3';
import * as utils from '@noble/curves/abstract/utils';
import { error } from 'console';

const CURVE_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513n


// The AVM represents points as their X and Y points concatenated
export function to_pxpy(input: Uint8Array): Uint8Array {
  const p = bls12_381.G1.ProjectivePoint.fromHex(utils.bytesToHex(input))
  return utils.concatBytes(utils.numberToBytesBE(p.x, 48), utils.numberToBytesBE(p.y, 48))
}

export function from_pxpy(input: Uint8Array): Uint8Array {
  const x = utils.bytesToNumberBE(input.slice(0, 48))
  const y = utils.bytesToNumberBE(input.slice(48, 96))
  return bls12_381.G1.ProjectivePoint.fromAffine({ x, y }).toRawBytes()
}

export function hash_point_to_ge(input: Uint8Array): Uint8Array {
  const pxpy = to_pxpy(input)
  const hash = keccak_256.create().update(pxpy).digest();
  const number = utils.hexToNumber(utils.bytesToHex(hash))
  //TODO: Need to look into implementing ExpandMsgXmd in AVM; and then call HashToCurve directly from Nobles
  return bls12_381.G1.ProjectivePoint.fromAffine(bls12_381.G1.mapToCurve([number]).toAffine()).toRawBytes();
}

export function hash_to_fe(...args: Uint8Array[]): Uint8Array {
  const hasher = keccak_256.create();
  for (let arg of args) {
    hasher.update(arg);
  }
  //TODO: Understand if this is introducing dangerous modulo bias
  return utils.numberToBytesBE(utils.hexToNumber(utils.bytesToHex(hasher.digest())) % CURVE_ORDER, 32);
}

export function generate_fe(): Uint8Array {
  return bls12_381.utils.randomPrivateKey();
}

export function generate_ge(fe: Uint8Array): Uint8Array {
  return bls12_381.getPublicKey(fe);
}

export function ec_add(p1: Uint8Array, p2: Uint8Array): Uint8Array {
  return bls12_381.G1.ProjectivePoint.fromHex(utils.bytesToHex(p1)).add(bls12_381.G1.ProjectivePoint.fromHex(utils.bytesToHex(p2))).toRawBytes();
}

export function ec_fe_mul(fe1: Uint8Array, fe2: Uint8Array): Uint8Array {
  return utils.numberToBytesBE(bls12_381.G1.normPrivateKeyToScalar(utils.bytesToNumberBE(fe1) * utils.bytesToNumberBE(fe2)), 32);
}

export function ec_fe_sub(fe1: Uint8Array, fe2: Uint8Array): Uint8Array {
  return utils.numberToBytesBE(bls12_381.G1.normPrivateKeyToScalar(utils.bytesToNumberBE(fe1) - utils.bytesToNumberBE(fe2)), 32);
}

export function ec_scalar_mul(p: Uint8Array | 1, scalar: Uint8Array): Uint8Array {
  if (p === 1) {
    return bls12_381.G1.ProjectivePoint.fromPrivateKey(scalar).toRawBytes();
  }
  return bls12_381.G1.ProjectivePoint.fromHex(utils.bytesToHex(p)).multiply(utils.bytesToNumberBE(scalar)).toRawBytes();
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
export function NIZK_DLOG_generate_proof(a: Uint8Array): [Uint8Array, Uint8Array, Uint8Array, Uint8Array] {
  const x = generate_ge(a); // x = g ^a
  const x_hashable = to_pxpy(x);

  const r = generate_fe(); // r < - Z_q
  const v = generate_ge(r); // v = g ^ r
  const v_hashable = to_pxpy(v);

  const g_hashable = to_pxpy(bls12_381.G1.ProjectivePoint.BASE.toRawBytes());

  // Compute the challenge c
  const concatenated = utils.concatBytes(g_hashable, x_hashable, v_hashable);
  const challenge = utils.numberToBytesBE(utils.bytesToNumberBE(keccak_256.create().update(concatenated).digest()) % 52435875175126190479447740508185965837690552500527637822603658699938581184513n, 32);

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

export function NIZK_DLOG_verify_proof(g_bytes: Uint8Array, x_bytes: Uint8Array, v_bytes: Uint8Array, z: Uint8Array): boolean {
  // Compute the challenge c
  const concatenated = utils.concatBytes(g_bytes, x_bytes, v_bytes);
  const challenge = utils.numberToBytesBE(utils.bytesToNumberBE(keccak_256.create().update(concatenated).digest()) % 52435875175126190479447740508185965837690552500527637822603658699938581184513n, 32);

  // The challenge can be between 0 and 2^256-1, but the scalar is between 0 and the curve order (approx 2^254.857089413)
  // TODO: Check if this biasing is acceptable, since everything over 52435875175126190479447740508185965837690552500527637822603658699938581184513
  // will loop over and we will get a bias towards lower numbers

  const v = bls12_381.G1.ProjectivePoint.fromHex(utils.bytesToHex(v_bytes)) // v_x sliced out
  const g = bls12_381.G1.ProjectivePoint.fromHex(utils.bytesToHex(g_bytes)).toRawBytes()
  const x = bls12_381.G1.ProjectivePoint.fromHex(utils.bytesToHex(x_bytes)).toRawBytes()

  const rhs = bls12_381.G1.ProjectivePoint.fromHex(
    utils.bytesToHex(
      ec_add(
        ec_scalar_mul(g, z),
        ec_scalar_mul(x, challenge)
      )
    )
  )

  return v.px === rhs.px && v.py === rhs.py && v.pz === rhs.pz;
}

export function genKeyImage(sk: Uint8Array, pk: Uint8Array): Uint8Array {
  // Generates key image, either from the actual SK and PK of the signer, or from a random scalar and PK in the ring
  const keyImage = hash_point_to_ge(pk);
  return ec_scalar_mul(keyImage, sk);
}

export function create_ring_link(msg: Uint8Array, r: Uint8Array, c: Uint8Array | 0, pk: Uint8Array, key_image: Uint8Array | 0): Uint8Array {
  if ((c === 0) || (key_image === 0)) {
    return hash_to_fe(msg, ec_scalar_mul(1, r), genKeyImage(r, pk));
  }
  return hash_to_fe(msg, ec_add(ec_scalar_mul(1, r), ec_scalar_mul(pk, c)), ec_add(genKeyImage(r, pk), ec_scalar_mul(key_image, c)));
}

function areEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((val, index) => val === b[index]);
}

export function getRandomShiftFactor(n: number): number {
  return Math.floor(Math.random() * n);
}

export function createRing(n: number, signerIdx: number, signerPk: Uint8Array): Uint8Array[] {
  let ring: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    if (i === signerIdx) {
      ring.push(signerPk);
    } else {
      ring.push(generate_ge(generate_fe()));
    }
  }
  return ring;
}

export function generate_ring_signature(
  msg: Uint8Array,
  sk: Uint8Array,
  ring: Uint8Array[],
  keyImage: Uint8Array): {
    signature: Uint8Array[],
    keyImage: Uint8Array,
  } {
  const pi = ring.findIndex(pk => areEqual(pk, generate_ge(sk)));
  if (pi === -1) {
    throw new Error('error: signer not found in ring');
  }
  const n = ring.length;

  let nonces: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    nonces.push(generate_fe());
  }

  let values: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    const j = (i + pi) % n;
    const k = (i + pi + 1) % n;

    if (j === pi) {
      values[k] = create_ring_link(msg, nonces[j], 0, ring[j], 0);
    } else {
      values[k] = create_ring_link(msg, nonces[j], values[j], ring[j], keyImage);
    }
  }

  const r_pi = ec_fe_sub(nonces[pi], ec_fe_mul(values[pi], sk));
  nonces[pi] = r_pi;

  let signature: Uint8Array[] = [];
  signature.push(values[0]);
  for (let i = 0; i < n; i++) {
    signature.push(nonces[i]);
  }

  if (!verify_ring_signature(msg, signature, ring, keyImage)) {
    throw new Error('error: generated ring signature not valid');
  }

  return { signature, keyImage };
}

export function verify_ring_signature(msg: Uint8Array, signature: Uint8Array[], ring: Uint8Array[], keyImage: Uint8Array): boolean {
  const n = ring.length;
  let values_prime: Uint8Array[] = [];
  values_prime[0] = signature[0];
  for (let i = 0; i < n - 1; i++) {
    values_prime[i + 1] = create_ring_link(msg, signature[i + 1], values_prime[i], ring[i], keyImage);
  }
  values_prime[0] = create_ring_link(msg, signature[n], values_prime[n - 1], ring[n - 1], keyImage);

  return areEqual(values_prime[0], signature[0]);
}

// Prepare Ring Signature for AVM App+LSig Combo Consumption
export function construct_avm_ring_signature(msg: Uint8Array, signature: Uint8Array[], ring: Uint8Array[], keyImage: Uint8Array): {
  msg: Uint8Array,
  signatureConcat: Uint8Array,
  intermediateValues: Uint8Array
} {
  const n = ring.length;
  let intermediateValues: Uint8Array[] = [];
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