import { generateKeyPairSync, KeyObject } from 'node:crypto';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { EntraIdIssuer, EntraIdV2Issuer } from '../../../src/issuer/entraid.js';

describe('entraid', () => {
  let publicKey: KeyObject;
  let privateKey: KeyObject;

  beforeAll(() => {
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
    publicKey = pair.publicKey;
    privateKey = pair.privateKey;
  });

  describe('EntraIdIssuer', () => {
    it('derives JWK URL from tenantId', () => {
      const issuer = new EntraIdIssuer('b93bd315-eefd-4876-bb82-9cc989d986cb');
      expect(issuer.tenantId).toBe('b93bd315-eefd-4876-bb82-9cc989d986cb');
      expect(issuer.jwksUri).toStrictEqual(new URL('https://login.microsoftonline.com/b93bd315-eefd-4876-bb82-9cc989d986cb/discovery/keys'));
    });

    describe('keyToJwk', () => {
      it('creates a normal JWK entry', () => {
        const issuer = new EntraIdIssuer('b93bd315-eefd-4876-bb82-9cc989d986cb');
        const { e, n } = publicKey.export({ format: 'jwk' });
        const result = issuer.keyToJwk({ kid: 'KID1', privateKey, publicKey });
        expect(result).toStrictEqual({
          e,
          kid: 'KID1',
          kty: 'RSA',
          n,
          use: 'sig',
        });
      });
    });

    describe('sampleHeader', () => {
      it('uses the KID of the first key', () => {
        const issuer = new EntraIdIssuer('b93bd315-eefd-4876-bb82-9cc989d986cb');
        issuer.addKey('KID1', privateKey, publicKey);

        expect(issuer.sampleHeader()).toStrictEqual({
          alg: 'RS256',
          kid: 'KID1',
          typ: 'JWT',
          x5t: 'KID1',
        });
      });
    });

    describe('samplePayload', () => {
      const frozenTimestampMillis = 1717871501123; // 2024-06-08T18:31:41.123Z
      const frozenTimestampSeconds = 1717871501; // 2024-06-08T18:31:41.123Z

      beforeEach(() => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date(frozenTimestampMillis));
      });

      afterEach(() => {
        vi.useRealTimers();
      });

      it('sets the expired time of 60 minutes', () => {
        const issuer = new EntraIdIssuer('b93bd315-eefd-4876-bb82-9cc989d986cb');

        expect(issuer.samplePayload()).toStrictEqual({
          exp: frozenTimestampSeconds + 30 * 60,
          iat: frozenTimestampSeconds,
          idp: 'https://sts.windows.net/b93bd315-eefd-4876-bb82-9cc989d986cb/',
          iss: 'https://sts.windows.net/b93bd315-eefd-4876-bb82-9cc989d986cb/',
          nbf: frozenTimestampSeconds,
          sub: 'QsdasdqQ-QWXjklIJjkljIp',
          tid: 'b93bd315-eefd-4876-bb82-9cc989d986cb',
          ver: '1.0',
        });
      });
    });
  });

  describe('EntraIdV2Issuer', () => {
    it('derives JWK URL from tenantId', () => {
      const issuer = new EntraIdV2Issuer('b93bd315-eefd-4876-bb82-9cc989d986cb');
      expect(issuer.tenantId).toBe('b93bd315-eefd-4876-bb82-9cc989d986cb');
      expect(issuer.jwksUri).toStrictEqual(new URL('https://login.microsoftonline.com/b93bd315-eefd-4876-bb82-9cc989d986cb/discovery/v2.0/keys'));
    });

    describe('keyToJwk', () => {
      it('creates a normal JWK entry', () => {
        const issuer = new EntraIdV2Issuer('b93bd315-eefd-4876-bb82-9cc989d986cb');
        const { e, n } = publicKey.export({ format: 'jwk' });
        const result = issuer.keyToJwk({ kid: 'KID1', privateKey, publicKey });
        expect(result).toStrictEqual({
          e,
          issuer: 'https://login.microsoftonline.com/b93bd315-eefd-4876-bb82-9cc989d986cb/v2.0',
          kid: 'KID1',
          kty: 'RSA',
          n,
          use: 'sig',
        });
      });
    });

    describe('sampleHeader', () => {
      it('uses the KID of the first key', () => {
        const issuer = new EntraIdV2Issuer('b93bd315-eefd-4876-bb82-9cc989d986cb');
        issuer.addKey('KID1', privateKey, publicKey);

        expect(issuer.sampleHeader()).toStrictEqual({
          alg: 'RS256',
          kid: 'KID1',
          typ: 'JWT',
        });
      });
    });

    describe('samplePayload', () => {
      const frozenTimestampMillis = 1717871501123; // 2024-06-08T18:31:41.123Z
      const frozenTimestampSeconds = 1717871501; // 2024-06-08T18:31:41.123Z

      beforeEach(() => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date(frozenTimestampMillis));
      });

      afterEach(() => {
        vi.useRealTimers();
      });

      it('sets the expired time of 60 minutes', () => {
        const issuer = new EntraIdV2Issuer('b93bd315-eefd-4876-bb82-9cc989d986cb');

        expect(issuer.samplePayload()).toStrictEqual({
          exp: frozenTimestampSeconds + 30 * 60,
          iat: frozenTimestampSeconds,
          iss: 'https://login.microsoftonline.com/b93bd315-eefd-4876-bb82-9cc989d986cb/v2.0',
          nbf: frozenTimestampSeconds,
          sub: 'QsdasdqQ-QWXjklIJjkljIp',
          tid: 'b93bd315-eefd-4876-bb82-9cc989d986cb',
          ver: '2.0',
        });
      });
    });
  });
});
