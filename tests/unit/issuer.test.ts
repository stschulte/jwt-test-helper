import nock from 'nock'
import { KeyObject, generateKeyPairSync } from 'node:crypto'
import { get } from 'node:https'
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

import { BaseIssuer, FakeKey, Issuer, jwsToCryptoAlgorithm } from '../../src/issuer.js'
import { JWK, JWKSet } from '../../src/jwk.js'
import { JOSEHeader, JWSAlgorithm, JWTClaims } from '../../src/jwt.js'

async function fetchJwk(url: string): Promise<JWKSet> {
  return new Promise((resolve, reject) => {
    get(url, (response) => {
      let body = ""
      response.on('data', (chunk) => {
        body += chunk
      })

      response.on('error', (error) => reject(error))

      response.on('end', () => {
        try {
          const json = JSON.parse(body)
          return resolve(json)
        }
        catch (error) {
          reject(error)
        }
      })
    })
  })
}

class SimpleIssuer extends BaseIssuer {
  keyToJwk(key: FakeKey): JWK {
    const { e, n } = key.publicKey.export({ format: 'jwk' })
    if (!e || !n) {
      throw new Error("keyToJWK was called without an RSA key at least we do not have 'e' and 'n'")
    }

    return {
      e,
      "kid": key.kid,
      "kty": 'RSA',
      n
    }
  }

  sampleHeader(): JOSEHeader {
    return {
      'alg': 'RS256',
      'kid': this.kid()
    }
  }

  samplePayload(): JWTClaims {
    return { 'iss': 'bob', 'sub': 'Alice' }
  }
}

describe("issuer", () => {
  let publicKey: KeyObject
  let privateKey: KeyObject

  beforeAll(() => {
    const result = generateKeyPairSync('rsa', { modulusLength: 2048 })
    publicKey = result.publicKey
    privateKey = result.privateKey
  })

  describe("jwsToCryptoAlgorithm", () => {
    const happyPath: Array<[JWSAlgorithm, string]> = [
      ['RS256', 'RSA-SHA256'],
      ['RS384', 'RSA-SHA384'],
      ['RS512', 'RSA-SHA512']
    ]

    it.each(happyPath)("should translate %s to %s", (input, expected) => {
      expect(jwsToCryptoAlgorithm(input)).toBe(expected)
    })

    it("should fail on unsupported algorithms", () => {
      expect(() => jwsToCryptoAlgorithm('ES512')).toThrow(/does not support the algorithm/)
    })
  })

  describe("BaseIssuer", () => {
    it("initializes with a string url", () => {
      const newIssuer = new SimpleIssuer("https://example.com/keys.json")
      expect(newIssuer.jwksUri).toStrictEqual(new URL("https://example.com/keys.json"))
      expect(newIssuer.keys).toStrictEqual([])
    })

    it("initializes with a URL object", () => {
      const issuer = new SimpleIssuer(new URL("https://example.com/keys.json"))
      expect(issuer.jwksUri).toStrictEqual(new URL("https://example.com/keys.json"))
      expect(issuer.keys).toStrictEqual([])
    })

    describe("addKey", () => {
      it("adds a new key to the array", () => {
        const issuer = new SimpleIssuer(new URL("https://example.com/keys.json"))
        const result = issuer.addKey('ABC', privateKey, publicKey)
        const expectedKey = { kid: "ABC", privateKey, publicKey }

        expect(result).toStrictEqual(expectedKey)
        expect(issuer.keys).toStrictEqual([expectedKey])
      })
    })

    describe("createJwt", () => {
      it("creates a token with header and payload", () => {
        const issuer = new SimpleIssuer("https://example.com/keys.json")
        const result = issuer.createJwt({ alg: 'none' }, { iss: 'https://example.com', sub: 'Alice' })
        expect(result.header).toStrictEqual({ alg: 'none' })
        expect(result.payload).toStrictEqual({ iss: 'https://example.com', sub: 'Alice' })
        expect(result.signature).toBeUndefined()
      })

      it("sets issuer", () => {
        const issuer = new SimpleIssuer("https://example.com/keys.json")
        const result = issuer.createJwt({ alg: 'none' }, { iss: 'https://example.com', sub: 'Alice' })
        expect(result.issuer).toBe(issuer)
      })
    })

    describe("createSampleJwt", () => {
      it("uses sampleHeader and samplePayload", () => {
        const issuer = new SimpleIssuer(new URL("https://example.com/keys.json"))
        issuer.addKey('SAMPLEKID', privateKey, publicKey)
        const jwt = issuer.createSampleJwt()
        expect(jwt.header).toStrictEqual({ alg: 'RS256', kid: 'SAMPLEKID' })
        expect(jwt.payload).toStrictEqual({ iss: 'bob', sub: 'Alice' })
        expect(jwt.signature).toBeUndefined()
      })

      it("uses merges header and payload with sample", () => {
        const issuer = new SimpleIssuer(new URL("https://example.com/keys.json"))
        issuer.addKey('SAMPLEKID', privateKey, publicKey)
        const jwt = issuer.createSampleJwt({ kid: 'OTHERKID', typ: 'JWT' }, { aud: 'https://example.com', sub: 'Bob' })
        expect(jwt.header).toStrictEqual({ alg: 'RS256', kid: 'OTHERKID', typ: 'JWT' })
        expect(jwt.payload).toStrictEqual({ aud: 'https://example.com', iss: 'bob', sub: 'Bob' })
        expect(jwt.signature).toBeUndefined()
      })

      it("sets the issuer", () => {
        const issuer = new SimpleIssuer(new URL("https://example.com/keys.json"))
        issuer.addKey('SAMPLEKID', privateKey, publicKey)
        const jwt = issuer.createSampleJwt()
        expect(jwt.issuer).toBe(issuer)
      })
    })

    describe("generateKey", () => {
      it("generates a new key and sets it", () => {
        const issuer = new SimpleIssuer(new URL("https://example.com/keys.json"))
        const newKey1 = issuer.generateKey()
        const newKey2 = issuer.generateKey()
        expect(issuer.keys).toStrictEqual([newKey1, newKey2])
      })

      it("generates a random kid when none provided", () => {
        const issuer = new SimpleIssuer(new URL("https://example.com/keys.json"))
        const { kid } = issuer.generateKey()
        expect(kid).toMatch(/^[0-9a-f]{40}$/)
      })

      it("uses the kid when provided", () => {
        const issuer = new SimpleIssuer(new URL("https://example.com/keys.json"))
        const { kid } = issuer.generateKey("KID1")
        expect(kid).toBe("KID1")
      })
    })
    describe("kid", () => {
      it("fails when no issuer has no key", () => {
        const issuer = new SimpleIssuer(new URL("https://example.com/keys.json"))
        expect(() => issuer.kid()).toThrow(/No key/)
      })

      it("fails when key does not exist", () => {
        const issuer = new SimpleIssuer(new URL("https://example.com/keys.json"))
        issuer.addKey('KID1', privateKey, publicKey)
        expect(() => issuer.kid(1)).toThrow(/No key/)
      })

      it("returns the first kid when no index provided", () => {
        const issuer = new SimpleIssuer(new URL("https://example.com/keys.json"))
        issuer.addKey('KID1', privateKey, publicKey)
        issuer.addKey('KID2', privateKey, publicKey)
        expect(issuer.kid()).toStrictEqual("KID1")
      })

      it("returns the kid with specified index", () => {
        const issuer = new SimpleIssuer(new URL("https://example.com/keys.json"))
        issuer.addKey('KID1', privateKey, publicKey)
        issuer.addKey('KID2', privateKey, publicKey)
        expect(issuer.kid(1)).toStrictEqual("KID2")
      })
    })

    describe("sign", () => {
      it("create a signature", () => {
        const issuer = new SimpleIssuer(new URL("https://example.com/keys.json"))
        issuer.addKey('KID1', privateKey, publicKey)
        const jwt = issuer.createSampleJwt()
        const signature = issuer.sign(jwt)

        expect(signature).not.toBeUndefined()
        expect(signature).toMatch(/\S+/)
      })

      it("does not update the signature for alg=none", () => {
        const issuer = new SimpleIssuer(new URL("https://example.com/keys.json"))
        issuer.addKey('KID1', privateKey, publicKey)
        const unsignedJwt = issuer.createJwt({ alg: 'none' }, { iss: 'bob', sub: 'Alice' })
        const signature = issuer.sign(unsignedJwt)
        expect(signature).toBeNull()
      })

      it("fails when kid is invalid", () => {
        const issuer = new SimpleIssuer(new URL("https://example.com/keys.json"))
        issuer.addKey('KID1', privateKey, publicKey)
        const jwt = issuer.createSampleJwt({ kid: 'foo' })
        expect(() => issuer.sign(jwt)).toThrow(/no key with kid foo/)
      })
    })

    describe("mockJwksUri", () => {
      beforeEach(() => {
        nock.disableNetConnect()
      })

      afterEach(() => {
        nock.cleanAll()
        nock.enableNetConnect()
      })

      it("mocks the call", async () => {
        const issuer = new SimpleIssuer(new URL("https://example.com/keys.json"))
        const { e, n } = publicKey.export({ format: 'jwk' })
        issuer.addKey('KID1', privateKey, publicKey)

        issuer.mockJwksUri()
        const response = await fetchJwk("https://example.com/keys.json")
        expect(response).toStrictEqual({
          keys: [
            {
              e,
              kid: 'KID1',
              kty: 'RSA',
              n
            }
          ]
        })
      })
    })
  })

  describe("Issuer", () => {
    describe("keyToJwk", () => {
      it("creates a valid JWK", () => {
        const issuer = new Issuer("https://example.com/keys.json")
        const { e, n } = publicKey.export({ format: 'jwk' })
        const key = { kid: "YEAH", privateKey, publicKey }

        const result = issuer.keyToJwk(key)
        expect(result).toStrictEqual({
          e,
          kid: "YEAH",
          kty: "RSA",
          n,
          use: "sig"
        })
      })

      it("throws an error on non-rsa keys", () => {
        const issuer = new Issuer("https://example.com/keys.json")
        const { privateKey, publicKey } = generateKeyPairSync('ed25519')
        const key = { kid: "Yeah", privateKey, publicKey }
        expect(() => issuer.keyToJwk(key)).toThrow(/was called without an RSA key/)
      })
    })

    describe("sampleHeader", () => {
      it("uses the KID of the first key", () => {
        const issuer = new Issuer("https://example.com/keys.json")
        issuer.addKey('KID1', privateKey, publicKey)

        expect(issuer.sampleHeader()).toStrictEqual({ alg: 'RS256', kid: 'KID1' })
      })
    })

    describe("samplePayload", () => {
      const frozenTimestampMillis = 1717871501123 //2024-06-08T18:31:41.123Z
      const frozenTimestampSeconds = 1717871501 //2024-06-08T18:31:41.123Z

      beforeEach(() => {
        vi.useFakeTimers()
        vi.setSystemTime(new Date(frozenTimestampMillis))
      })

      afterEach(() => {
        vi.useRealTimers()
      })

      it("sets the expired time of 60 minutes", () => {
        const issuer = new Issuer("https://example.com/keys.json")
        expect(issuer.samplePayload()).toStrictEqual({ exp: frozenTimestampSeconds + 30 * 60 })
      })
    })
  })
})
