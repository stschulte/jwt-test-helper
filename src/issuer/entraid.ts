import type { FakeKey } from '../issuer.js';
import type { JWKRSAPublicKey } from '../jwk.js';
import type { JOSEHeader, JWTClaims } from '../jwt.js';

import { BaseIssuer } from '../issuer.js';
import { rsaKeyToJwk } from '../jwk.js';

interface EntraIdClaims extends JWTClaims {
  aio?: string;
  amr?: Array<'mfa' | 'pwd' | 'rsa'>;
  email?: string;
  family_name?: string;
  given_name?: string;
  idp?: string;
  ipaddr?: string;
  name?: string;
  nonce?: string;
  oid?: string;
  rh?: string;
  tid?: string;
  unique_name?: string;
  uti?: string;
  ver: '1.0';
}

interface EntraIdV2Claims extends JWTClaims {
  aio?: string;
  name?: string;
  nonce?: string;
  oid?: string;
  preferred_username?: string;
  tid?: string;
  ver: '2.0';
}

interface EntraIdJWK extends JWKRSAPublicKey {
  kid: string;
  kty: 'RSA';
  use: 'sig';
}

interface EntraIdV2JWK extends JWKRSAPublicKey {
  issuer: string;
  kid: string;
  kty: 'RSA';
  use: 'sig';
}

export class EntraIdIssuer extends BaseIssuer<EntraIdClaims, EntraIdJWK> {
  tenantId: string;

  constructor(tenantId: string) {
    super(`https://login.microsoftonline.com/${tenantId}/discovery/keys`);
    this.tenantId = tenantId;
  }

  keyToJwk(key: FakeKey): EntraIdJWK {
    const { e, n } = rsaKeyToJwk(key.kid, key.publicKey);
    return {
      e,
      kid: key.kid,
      kty: 'RSA',
      n,
      use: 'sig',
    };
  }

  sampleHeader(): JOSEHeader {
    const kid = this.kid();
    return {
      alg: 'RS256',
      kid: kid,
      typ: 'JWT',
      x5t: kid,
    };
  }

  samplePayload(): EntraIdClaims {
    return {
      exp: Math.floor(Date.now() / 1000 + 1800),
      iat: Math.floor(Date.now() / 1000),
      idp: `https://sts.windows.net/${this.tenantId}/`,
      iss: `https://sts.windows.net/${this.tenantId}/`,
      nbf: Math.floor(Date.now() / 1000),
      sub: 'QsdasdqQ-QWXjklIJjkljIp',
      tid: this.tenantId,
      ver: '1.0',
    };
  }
}

export class EntraIdV2Issuer extends BaseIssuer<EntraIdV2Claims, EntraIdV2JWK> {
  tenantId: string;

  constructor(tenantId: string) {
    super(`https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`);
    this.tenantId = tenantId;
  }

  keyToJwk(key: FakeKey): EntraIdV2JWK {
    const { e, n } = rsaKeyToJwk(key.kid, key.publicKey);
    return {
      e,
      issuer: `https://login.microsoftonline.com/${this.tenantId}/v2.0`,
      kid: key.kid,
      kty: 'RSA',
      n,
      use: 'sig',
    };
  }

  sampleHeader(): JOSEHeader {
    return {
      alg: 'RS256',
      kid: this.kid(),
      typ: 'JWT',
    };
  }

  samplePayload(): EntraIdV2Claims {
    return {
      exp: Math.floor(Date.now() / 1000 + 1800),
      iat: Math.floor(Date.now() / 1000),
      iss: `https://login.microsoftonline.com/${this.tenantId}/v2.0`,
      nbf: Math.floor(Date.now() / 1000),
      sub: 'QsdasdqQ-QWXjklIJjkljIp',
      tid: this.tenantId,
      ver: '2.0',
    };
  }
}
