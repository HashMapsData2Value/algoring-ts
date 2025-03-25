export declare function to_pxpy(input: Uint8Array): Uint8Array;
export declare function from_pxpy(input: Uint8Array): Uint8Array;
export declare function hash_point_to_ge(input: Uint8Array): Uint8Array;
export declare function hash_to_fe(...args: Uint8Array[]): Uint8Array;
export declare function generate_fe(): Uint8Array;
export declare function generate_ge(fe: Uint8Array): Uint8Array;
export declare function ec_add(p1: Uint8Array, p2: Uint8Array): Uint8Array;
export declare function ec_fe_mul(fe1: Uint8Array, fe2: Uint8Array): Uint8Array;
export declare function ec_fe_sub(fe1: Uint8Array, fe2: Uint8Array): Uint8Array;
export declare function ec_scalar_mul(p: Uint8Array | 1, scalar: Uint8Array): Uint8Array;
export declare function NIZK_DLOG_generate_proof(a: Uint8Array): [Uint8Array, Uint8Array, Uint8Array, Uint8Array];
export declare function NIZK_DLOG_verify_proof(g_bytes: Uint8Array, x_bytes: Uint8Array, v_bytes: Uint8Array, z: Uint8Array): boolean;
export declare function genKeyImage(sk: Uint8Array, pk: Uint8Array): Uint8Array;
export declare function create_ring_link(msg: Uint8Array, r: Uint8Array, c: Uint8Array | 0, pk: Uint8Array, key_image: Uint8Array | 0): Uint8Array;
export declare function getRandomShiftFactor(n: number): number;
export declare function createRing(n: number, signerIdx: number, signerPk: Uint8Array): Uint8Array[];
export declare function generate_ring_signature(msg: Uint8Array, sk: Uint8Array, ring: Uint8Array[], keyImage: Uint8Array): {
    signature: Uint8Array[];
    keyImage: Uint8Array;
};
export declare function verify_ring_signature(msg: Uint8Array, signature: Uint8Array[], ring: Uint8Array[], keyImage: Uint8Array): boolean;
export declare function construct_avm_ring_signature(msg: Uint8Array, signature: Uint8Array[], ring: Uint8Array[], keyImage: Uint8Array): {
    msg: Uint8Array;
    signatureConcat: Uint8Array;
    intermediateValues: Uint8Array;
};
