import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { Issuer } from '../../src/issuer.js';
import { joinJwt, jsonbase64url, JWT } from '../../src/jwt.js';

describe('jwt', () => {
  describe('jsonbase64url', () => {
    it('converts to base64url', () => {
      expect(jsonbase64url({ alg: 'none', aud: ['foo', 'aaßßa'] })).toBe('eyJhbGciOiJub25lIiwiYXVkIjpbImZvbyIsImFhw5_Dn2EiXX0');
    });
  });

  describe('joinJwt', () => {
    it('joins token with signature', () => {
      const signature = 'cxMfyUBinldRVMISd9hQXMf38XTUci10WVjcWMs7u0IGXlzfJxWfPvOg0TMr2gzT2GHGttG_qZEkp7Iq4_ysKr9qNQbq2kYBI64ztVqfT-A4_sBBNTFD7WTIcTURpQYjV1oJHHCSg_GoFFGBZCMU91rrQ_LBlTjdPjhQveNpL7M-tv-d1ChjvFZ5F6D69hpEqxDjBaM5LrjrTmoFliJsAub_oxVCmpONFz42MZZRMN_oqxmh1d2CK2SKx6wm_VJbvUwm_k4Bc01sV6PFwrRMB16xQZ1E1eksVmT3EUopXmYLSv7dgZvEQKCfAxAGGb7X5b_Q25BzGVq4OUqlzKwvbQ';
      expect(joinJwt({ alg: 'RS256', kid: 'k1' }, { iss: 'joe' }, signature)).toBe(`eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.eyJpc3MiOiJqb2UifQ.${signature}`);
    });

    it('creates unsigned tokens according to rfc7519 6.1', () => {
      expect(joinJwt({ alg: 'none' }, { iss: 'joe' })).toBe('eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UifQ.');
    });
  });

  describe('JWt', () => {
    let issuer: Issuer;
    let jwt: JWT;
    const frozenTimestampMillis = 1717871501123; // 2024-06-08T18:31:41.123Z
    const frozenTimestampSeconds = 1717871501; // 2024-06-08T18:31:41.123Z

    beforeAll(() => {
      issuer = new Issuer('htts://example.com/keys.json');
      issuer.generateKey();
      issuer.generateKey('K1');
    });

    beforeEach(() => {
      jwt = new JWT(issuer, { alg: 'RS256', kid: issuer.kid(0) }, { exp: 1717870522, iss: 'joe', sub: 'alice' });

      vi.useFakeTimers();
      vi.setSystemTime(new Date(frozenTimestampMillis));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('creates a new Jwt with header and payload', () => {
      const issuer = new Issuer('htts://example.com/keys.json');
      const jwt = new JWT(issuer, { alg: 'RS256', kid: 'K1' }, { iss: 'joe', sub: 'alice' });
      expect(jwt.issuer).toBe(issuer);
      expect(jwt.header).toStrictEqual({ alg: 'RS256', kid: 'K1' });
      expect(jwt.payload).toStrictEqual({ iss: 'joe', sub: 'alice' });
      expect(jwt.signature).toBeUndefined();
    });

    describe('becomesValidInSeconds', () => {
      it('overwrites the nbf claim', () => {
        jwt.becomesValidInSeconds(120);
        expect(jwt.payload.nbf).toBe(frozenTimestampSeconds + 120);
      });

      it('returns itself', () => {
        expect(jwt.becomesValidInSeconds(120)).toBe(jwt);
      });
    });

    describe('expireAt', () => {
      it('updates the expiration time', () => {
        jwt.expireAt(1717870670);
        expect(jwt.payload.exp).toBe(1717870670);
      });

      it('returns itself', () => {
        expect(jwt.expireAt(1717871501123)).toBe(jwt);
      });
    });

    describe('expireInSeconds', () => {
      it('overwrites the exp claim', () => {
        jwt.expireInSeconds(120);
        expect(jwt.payload.exp).toBe(frozenTimestampSeconds + 120);
      });

      it('returns itself', () => {
        expect(jwt.expireInSeconds(60)).toBe(jwt);
      });
    });

    describe('expireNow', () => {
      it('updates the exp claim to the current time', () => {
        jwt.expireNow();
        expect(jwt.payload.exp).toBe(frozenTimestampSeconds);
      });

      it('returns itself', () => {
        expect(jwt.expireNow()).toBe(jwt);
      });
    });

    describe('expired', () => {
      it('sets the exp claim 1 minute in the past', () => {
        const past = frozenTimestampSeconds - 60;
        jwt.expired();
        expect(jwt.payload.exp).toBe(past);
      });

      it('returns itself', () => {
        expect(jwt.expired()).toBe(jwt);
      });
    });

    describe('withAudience', () => {
      it('updates the aud claim', () => {
        jwt.withAudience('http://example.com');
        expect(jwt.payload.aud).toBe('http://example.com');
      });

      it('returns itself', () => {
        expect(jwt.withAudience('http://example.com')).toBe(jwt);
      });
    });

    describe('withSubject', () => {
      it('updates the sub claim', () => {
        jwt.withSubject('Alan');
        expect(jwt.payload.sub).toBe('Alan');
      });

      it('updates itself', () => {
        expect(jwt.withSubject('Alan')).toBe(jwt);
      });
    });

    describe('withIssuer', () => {
      it('updates the iss claim', () => {
        jwt.withIssuer('https://issuer.net');
        expect(jwt.payload.iss).toBe('https://issuer.net');
      });

      it('updates itself', () => {
        expect(jwt.withIssuer('https://issuer.net')).toBe(jwt);
      });
    });

    describe('sign', () => {
      it('updates the signature', () => {
        const expectedSignature = issuer.sign(jwt);
        jwt.sign();
        expect(jwt.signature).not.toBeUndefined();
        expect(jwt.signature).toBe(expectedSignature);
      });

      it('does not update the signature for alg=none', () => {
        const unsignedJwt = issuer.createJwt({ alg: 'none' }, { iss: 'bob', sub: 'Alice' });
        unsignedJwt.sign();
        expect(unsignedJwt.signature).toBeUndefined();
      });

      it('fails when kid is invalid', () => {
        const invalidJwt = issuer.createJwt({ alg: 'RS256', kid: 'FOO' }, { iss: 'bob', sub: 'Alice' });
        expect(() => invalidJwt.sign()).toThrow(/no key with kid FOO/);
      });

      it('returns itself', () => {
        expect(jwt.sign()).toBe(jwt);
      });
    });

    describe('prettyPrint', () => {
      describe('signed token', () => {
        it('prints the token', () => {
          const signedJwt = issuer.createJwt({ alg: 'RS256', kid: 'K1' }, { iss: 'bob', sub: 'Alice' }).sign();
          expect(signedJwt.prettyPrint()).toBe(`{
  "alg": "RS256",
  "kid": "K1"
}.{
  "iss": "bob",
  "sub": "Alice"
}.[Signature]`);
        });

        it('prints the complete signature on includeSignature', () => {
          const signedJwt = issuer.createJwt({ alg: 'RS256', kid: 'K1' }, { iss: 'bob', sub: 'Alice' }).sign();
          const signature = signedJwt.signature ?? '';
          expect(signedJwt.prettyPrint(true)).toBe(`{
  "alg": "RS256",
  "kid": "K1"
}.{
  "iss": "bob",
  "sub": "Alice"
}.${signature}`);
        });
      });

      describe('unsigned token', () => {
        it('prints the token', () => {
          const unsignedJwt = issuer.createJwt({ alg: 'none' }, { iss: 'bob', sub: 'Alice' });
          expect(unsignedJwt.prettyPrint()).toBe(`{
  "alg": "none"
}.{
  "iss": "bob",
  "sub": "Alice"
}.[No Signature]`);
        });

        it('ignores includeSignature', () => {
          const unsignedJwt = issuer.createJwt({ alg: 'none' }, { iss: 'bob', sub: 'Alice' });
          expect(unsignedJwt.prettyPrint(true)).toBe(`{
  "alg": "none"
}.{
  "iss": "bob",
  "sub": "Alice"
}.[No Signature]`);
        });
      });
    });

    describe('toString', () => {
      it('should return an unsigned token according to RFC 7519 Section 6', () => {
        const unsignedJwt = issuer.createJwt({ alg: 'none', kid: 'K1' }, { iss: 'bob', sub: 'Alice' });
        expect(unsignedJwt.toString()).toBe('eyJhbGciOiJub25lIiwia2lkIjoiSzEifQ.eyJpc3MiOiJib2IiLCJzdWIiOiJBbGljZSJ9.');
      });

      it('should return a signed token', () => {
        const signedJwt = issuer.createJwt({ alg: 'RS256', kid: 'K1' }, { iss: 'bob', sub: 'Alice' }).sign();
        const signature = signedJwt.signature ?? '';
        expect(signedJwt.toString()).toBe(`eyJhbGciOiJSUzI1NiIsImtpZCI6IksxIn0.eyJpc3MiOiJib2IiLCJzdWIiOiJBbGljZSJ9.${signature}`);
      });
    });

    describe('updateClaims', () => {
      it('merges new fields with the payload', () => {
        const fakeJwt = issuer.createJwt({ alg: 'RS256', kid: 'K1' }, { iss: 'bob', sub: 'Alice' });
        fakeJwt.updateClaims({ aud: 'https://example.com', sub: 'Joe' });
        expect(fakeJwt.payload).toStrictEqual({ aud: 'https://example.com', iss: 'bob', sub: 'Joe' });
      });

      it('returns itself', () => {
        expect(jwt.updateClaims({ sub: 'Alice' })).toBe(jwt);
      });
    });

    describe('updateHeader', () => {
      it('merges new fields with the header', () => {
        const fakeJwt = issuer.createJwt({ alg: 'RS256', kid: 'K1' }, { iss: 'bob', sub: 'Alice' });
        fakeJwt.updateHeader({ kid: 'K2', typ: 'JWT' });
        expect(fakeJwt.header).toStrictEqual({ alg: 'RS256', kid: 'K2', typ: 'JWT' });
      });

      it('returns itself', () => {
        expect(jwt.updateHeader({ typ: 'JWT' })).toBe(jwt);
      });
    });

    describe('unknownKid', () => {
      it('sets a random key id', () => {
        const fakeJwt = issuer.createJwt({ alg: 'RS256', kid: 'K1' }, { iss: 'bob', sub: 'Alice' });
        fakeJwt.unknownKid();
        expect(fakeJwt.header.kid).not.toBe('K1');
        expect(fakeJwt.header.kid).toMatch(/^[0-9a-z]{40}$/);
      });

      it('returns itself', () => {
        expect(jwt.unknownKid()).toBe(jwt);
      });
    });

    describe('withoutKeyId', () => {
      it('removes an existing kid header', () => {
        const fakeJwt = issuer.createJwt({ alg: 'RS256', kid: 'K1' }, { iss: 'bob', sub: 'Alice' }).withoutKeyId();
        expect(fakeJwt.header.kid).toBeUndefined();
        expect(fakeJwt.header).toStrictEqual({ alg: 'RS256' });
      });

      it('does nothing when kid already absent', () => {
        const fakeJwt = issuer.createJwt({ alg: 'RS256' }, { iss: 'bob', sub: 'Alice' }).withoutKeyId();
        expect(fakeJwt.header.kid).toBeUndefined();
        expect(fakeJwt.header).toStrictEqual({ alg: 'RS256' });
      });
    });
  });
});
