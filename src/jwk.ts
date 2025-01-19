import { KeyObject } from 'node:crypto';

export type JWK = JWKEllipticCurvePublicKey | JWKRSAPublicKey | JWKSymmetricKey;

// https://datatracker.ietf.org/doc/html/rfc7517#section-4
export type JWKCommon = {
  [key: string]: string | string[];
  'alg'?: Alg; // Algorithm
  'key_ops'?: KeyOperations[]; // Key Operations
  'kid'?: string; // Key ID
  'kty': KeyType; // Key Type MUST be present
  'use'?: PublicKeyUse; // Public Key Use
  'x5c'?: string[]; // X.509 Certificate Chain
  'x5t'?: string; // X.509 Certificate SHA-1 Thumbprint
  'x5t#S256'?: string; // X.509 Certificate SHA-256 Thumbprint
  'x5u'?: string; // X.509 URL
};
// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2
export type JWKEllipticCurvePublicKey = JWKCommon & {
  crv: 'P-256' | 'P-384' | 'P-521';
  kty: 'EC';
  x: string;
  y: string;
};
// https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1
export type JWKRSAPublicKey = JWKCommon & {
  e: string;
  kty: 'RSA';
  n: string;
};

// https://datatracker.ietf.org/doc/html/rfc7517#section-5
export interface JWKSet {
  keys: JWK[];
}

// https://datatracker.ietf.org/doc/html/rfc7518#section-6.4
export type JWKSymmetricKey = JWKCommon & {
  k: string;
  kty: 'oct';
};

// https://www.rfc-editor.org/rfc/rfc7518#section-7.1.2
type Alg = 'A128CBC-HS256'
  | 'A128GCM'
  | 'A128GCMKW'
  | 'A128KW'
  | 'A192CBC-HS384'
  | 'A192GCM'
  | 'A192GCMKW'
  | 'A192KW'
  | 'A256CBC-HS512'
  | 'A256GCM'
  | 'A256GCMKW'
  | 'A256KW'
  | 'dir'
  | 'ECDH-ES'
  | 'ECDH-ES+A128KW'
  | 'ECDH-ES+A192KW'
  | 'ECDH-ES+A256KW'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'HS256'
  | 'HS384'
  | 'HS512'
  | 'none'
  | 'PBES2-HS256+A128KW'
  | 'PBES2-HS384+A192KW'
  | 'PBES2-HS512+A256KW'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'RSA1_5'
  | 'RSA-OAEP'
  | 'RSA-OAEP-256';

type KeyOperations = 'decrypt' | 'deriveBits' | 'deriveKey' | 'encrypt' | 'sign' | 'unwrapKey' | 'verify' | 'wrapKey';

// https://www.rfc-editor.org/rfc/rfc7518.html#page-28
type KeyType = 'EC' | 'oct' | 'RSA';

type PublicKeyUse = 'enc' | 'sig';

class NoRSAKey extends Error { }

export function rsaKeyToJwk(kid: string, publicKey: KeyObject): JWKRSAPublicKey {
  const { e, n } = publicKey.export({ format: 'jwk' });
  if (!e || !n) {
    throw new NoRSAKey('keyToJWK was called without an RSA key at least we do not have \'e\' and \'n\'');
  }

  return {
    e,
    kid,
    kty: 'RSA',
    n,
    use: 'sig',
  };
}
