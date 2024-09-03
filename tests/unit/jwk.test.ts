import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { rsaKeyToJwk } from '../../src/jwk.js';

describe('jwk', () => {
  describe('rsaKeyToJwk', () => {
    it('creates a valid JWK', () => {
      const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
      const { e, n } = publicKey.export({ format: 'jwk' });

      expect(rsaKeyToJwk('KID1', publicKey)).toStrictEqual({
        e,
        kid: 'KID1',
        kty: 'RSA',
        n,
        use: 'sig',
      });
    });

    it('throws an error on non-rsa keys', () => {
      const { publicKey } = generateKeyPairSync('ed25519');
      expect(() => rsaKeyToJwk('KID1', publicKey)).toThrow(/was called without an RSA key/);
    });
  });
});
