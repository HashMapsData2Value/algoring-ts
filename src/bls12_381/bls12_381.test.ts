import {
  generate_fe,
  generate_ge,
  generate_ring_signature,
  verify_ring_signature,
  getRandomShiftFactor,
  createRing,
  genKeyImage,
  hash_point_to_ge,
  NIZK_DLOG_generate_proof,
  NIZK_DLOG_verify_proof,
  to_pxpy,
  construct_avm_ring_signature,
} from './bls12_381';
import { TextEncoder } from 'util';

describe('Ring Signature', () => {
  let sk: Uint8Array;
  let pk: Uint8Array;
  let number_of_participants: number;
  let ring: Uint8Array[];
  let msg: Uint8Array;
  let keyImage: Uint8Array;

  beforeAll(() => {
    sk = generate_fe();
    pk = generate_ge(sk);
    number_of_participants = 6;

    const pi = getRandomShiftFactor(number_of_participants);
    ring = createRing(number_of_participants, pi, pk);

    keyImage = genKeyImage(sk, pk);

    const msg_string = 'Sign this message';
    msg = new TextEncoder().encode(msg_string); // this is the message we want to sign
  });

  it('should generate and verify a ring signature', () => {
    const { signature } = generate_ring_signature(msg, sk, ring, keyImage);

    expect(verify_ring_signature(msg, signature, ring, keyImage)).toBe(true);
  });

  it('should generate an avm-compatible ring signature', () => {
    const { signature } = generate_ring_signature(msg, sk, ring, keyImage);

    construct_avm_ring_signature(msg, signature, ring, keyImage);

  });

  it('should fail to verify a ring signature with a different message', () => {
    const { signature } = generate_ring_signature(msg, sk, ring, keyImage);

    const msg_string = 'Sign this message instead';
    const msg_diff = new TextEncoder().encode(msg_string);

    expect(verify_ring_signature(msg_diff, signature, ring, keyImage)).toBe(false);
  });

  it('should give me expected hashtopoint', () => {
    const point = new Uint8Array([
      129, 119, 132, 19, 185, 32, 6, 229, 84, 7,
      31, 32, 239, 187, 118, 12, 109, 123, 234, 165,
      95, 213, 254, 114, 217, 182, 228, 87, 167, 229,
      30, 148, 86, 253, 18, 12, 44, 12, 4, 130,
      128, 61, 218, 57, 199, 47, 227, 167
    ])

    const new_point = hash_point_to_ge(point)

    expect(new_point).toStrictEqual(new Uint8Array([
      153, 147, 4, 225, 116, 61, 24, 64, 22, 31,
      12, 65, 244, 78, 19, 85, 234, 199, 84, 11,
      186, 208, 132, 146, 106, 8, 145, 4, 22, 2,
      197, 91, 24, 136, 80, 147, 150, 180, 136, 6,
      63, 189, 9, 178, 238, 112, 220, 167
    ]));
  });

  it('should produce a valid NIZK proof', () => {

    const a = new Uint8Array([
      105, 34, 160, 146, 247, 198, 138,
      255, 183, 107, 228, 18, 26, 143,
      50, 254, 238, 14, 191, 86, 236,
      129, 232, 87, 208, 105, 143, 22,
      165, 223, 156, 180
    ]);

    const proof = NIZK_DLOG_generate_proof(a);

    expect(proof[0]).toStrictEqual(new Uint8Array([
      23, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140,
      79, 169, 172, 15, 195, 104, 140, 79, 151, 116, 185, 5,
      161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63,
      249, 122, 26, 239, 251, 58, 240, 10, 219, 34, 198, 187,
      8, 179, 244, 129, 227, 170, 160, 241, 160, 158, 48, 237,
      116, 29, 138, 228, 252, 245, 224, 149, 213, 208, 10, 246,
      0, 219, 24, 203, 44, 4, 179, 237, 208, 60, 199, 68,
      162, 136, 138, 228, 12, 170, 35, 41, 70, 197, 231, 225
    ]));

    expect(proof[1]).toStrictEqual(new Uint8Array([
      7, 122, 95, 31, 116, 69, 4, 0, 55, 44, 1, 3,
      202, 39, 80, 43, 92, 5, 234, 160, 108, 74, 168, 65,
      1, 22, 218, 119, 132, 149, 161, 235, 183, 189, 31, 108,
      187, 170, 225, 104, 191, 154, 5, 69, 173, 250, 178, 115,
      21, 175, 15, 16, 21, 57, 45, 0, 35, 249, 121, 250,
      4, 124, 229, 231, 50, 158, 160, 12, 22, 206, 190, 41,
      106, 102, 22, 199, 119, 108, 39, 81, 211, 193, 255, 3,
      182, 55, 84, 79, 184, 0, 171, 248, 103, 56, 131, 196
    ]));

    // Proof[0] Contains the g in g^a = x, i.e. the generator. For now it is fixed but there could be situations where you want to provide a separate one.
    // Proof[1] Contains the x in g^a = x. This is fixed as well and could be provided from the outside.
    // Proof[2] Contains the v in g^r = v. This is the random value generated by the prover and is different each time.
    // Proof[3] Contains the z in z = r - c * a. This is dependent on r so it is different each time.
    // Note that the proof is so verbose because it will be fed into the AVM which might be more general. g and maybe even x could have been provided separately. 

    expect(proof[0].length).toBe(96);
    expect(proof[1].length).toBe(96);
    expect(proof[2].length).toBe(96);
    expect(proof[3].length).toBe(32);

    expect(NIZK_DLOG_verify_proof(proof[0], proof[1], proof[2], proof[3])).toBe(true);

    const bad_proof0 = structuredClone(proof)
    bad_proof0[0][0] = bad_proof0[0][0] + 1;
    expect(() => NIZK_DLOG_verify_proof(bad_proof0[0], bad_proof0[1], bad_proof0[2], bad_proof0[3])).toThrow('bad point: equation left != right');

    const bad_proof1 = structuredClone(proof)
    bad_proof1[1][0] = bad_proof1[1][0] + 1;
    expect(() => NIZK_DLOG_verify_proof(bad_proof1[0], bad_proof1[1], bad_proof1[2], bad_proof1[3])).toThrow('bad point: equation left != right');

    const bad_proof2 = structuredClone(proof)
    bad_proof2[2][0] = bad_proof2[2][0] + 1;
    expect(() => NIZK_DLOG_verify_proof(bad_proof2[0], bad_proof2[1], bad_proof2[2], bad_proof2[3])).toThrow('bad point: equation left != right');

    const bad_proof3 = structuredClone(proof)
    bad_proof3[3][0] = bad_proof3[3][0] + 1;
    expect(NIZK_DLOG_verify_proof(bad_proof3[0], bad_proof3[1], bad_proof3[2], bad_proof3[3])).toBe(false);

    expect(() => NIZK_DLOG_verify_proof(bad_proof3[0], bad_proof3[1], bad_proof3[2], new Uint8Array(32))).toThrow('expected valid scalar: 1 <= n < 52435875175126190479447740508185965837690552500527637822603658699938581184513, got 0');
  });

});