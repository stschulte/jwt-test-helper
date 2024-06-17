import nock from 'nock'
import { KeyObject, createSign, generateKeyPairSync, randomBytes } from 'node:crypto'

import type { JWK, JWKSet } from './jwk.js'
import type { JOSEHeader, JWSAlgorithm, JWTClaims } from './jwt.js'

import { rsaKeyToJwk } from './jwk.js'
import { JWT, jsonbase64url } from './jwt.js'

export class AlgorithmNotSupportedError extends Error { }
export class KeyIdNotFoundError extends Error { }

type SupportedCryptoAlgorithm = 'RSA-SHA256' | 'RSA-SHA384' | 'RSA-SHA512'

export function jwsToCryptoAlgorithm(alg: JWSAlgorithm): SupportedCryptoAlgorithm {
  if (alg === 'RS256') {
    return 'RSA-SHA256'
  } else if (alg === 'RS384') {
    return 'RSA-SHA384'
  } else if (alg === 'RS512') {
    return 'RSA-SHA512'
  }
  throw new AlgorithmNotSupportedError(`The jwt-test-helper does not support the algorithm. Expected: RS256, RS384, RS512; Got: ${alg}`)
}

export interface FakeKey {
  kid: string
  privateKey: KeyObject
  publicKey: KeyObject
}

export abstract class BaseIssuer<CustomJWTClaims extends JWTClaims = JWTClaims, CustomJWK extends JWK = JWK> {
  jwksUri: URL
  keys: FakeKey[]

  constructor(jwksUri: URL | string) {
    this.jwksUri = jwksUri instanceof URL ? jwksUri : new URL(jwksUri)
    this.keys = []
  }

  addKey(kid: string, privateKey: KeyObject, publicKey: KeyObject): FakeKey {
    const key = { kid, privateKey, publicKey }
    this.keys.push(key)
    return key
  }

  createJwt(header: JOSEHeader, payload: CustomJWTClaims): JWT<CustomJWTClaims> {
    return new JWT<CustomJWTClaims>(this, header, payload)
  }

  createSampleJwt(header: Partial<JOSEHeader> = {}, payload: Partial<CustomJWTClaims> = {}): JWT<CustomJWTClaims> {
    return new JWT<CustomJWTClaims>(this, Object.assign(this.sampleHeader(), header), Object.assign(this.samplePayload(), payload))
  }

  generateKey(kid?: string): FakeKey {
    const keyId = kid ? kid : randomBytes(20).toString('hex')
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
    return this.addKey(keyId, privateKey, publicKey)
  }

  kid(index = 0): string {
    const kid = this.keys[index]?.kid
    if (!kid) {
      throw new Error("No key created for issuer. Did you run generateKey() first?")
    }
    return kid
  }

  mockJwksUri() {
    const body: JWKSet = {
      "keys": this.keys.map((k) => this.keyToJwk(k))
    }
    const scope = nock(this.jwksUri).persist().get("").reply(200, body)
    return scope
  }

  sign(jwt: JWT): null | string {
    const { alg, kid } = jwt.header
    if (!alg || alg === 'none') {
      return null
    }

    const key = this.keys.find(k => k.kid === kid)
    if (!key) {
      throw new KeyIdNotFoundError(`Fake issuer has no key with kid ${kid}. Did you run generateKey first?`)
    }

    const signPayload = [
      jsonbase64url(jwt.header),
      jsonbase64url(jwt.payload)
    ].join(".")

    const signer = createSign(jwsToCryptoAlgorithm(alg))
    signer.write(signPayload)
    signer.end()

    return signer.sign(key.privateKey, 'base64url')
  }

  abstract keyToJwk(key: FakeKey): CustomJWK

  abstract sampleHeader(): JOSEHeader
  abstract samplePayload(): CustomJWTClaims
}

export class Issuer extends BaseIssuer<JWTClaims, JWK> {
  keyToJwk(key: FakeKey): JWK {
    return rsaKeyToJwk(key.kid, key.publicKey)
  }

  sampleHeader(): JOSEHeader {
    return {
      'alg': 'RS256',
      'kid': this.kid()
    }
  }

  samplePayload(): JWTClaims {
    return { 'exp': Math.floor(Date.now() / 1000 + 1800) }
  }
}
