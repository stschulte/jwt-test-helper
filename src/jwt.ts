import { randomBytes } from 'node:crypto'

import { BaseIssuer } from './issuer.js'

/**
 * Valid JWS Algorithms according to RFC7518 - JSON Web Algorithms (JWA)
 *
 * [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#section-3.1)
 */
export type JWSAlgorithm = 'ES256'
  | 'ES384'
  | 'ES512'
  | 'HS256'
  | 'HS256'
  | 'HS384'
  | 'HS512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'none'

/**
 * Registered Header Parameter names according to
 * RFC 7515 - JSON Web Signatures
 *
 * [RFC7515](https://www.rfc-editor.org/rfc/rfc7515#section-4.1)
 */
export interface JOSEHeader {
  alg: JWSAlgorithm // Algorithm
  crit?: string[] // Critical
  cty?: string // Content Type
  jku?: string  // JWK Set Url
  jwk?: string // JSON Web Key
  kid?: string // Key ID
  typ?: string // Type
  x5c?: string[] // X509 Certificate Chain
  x5t?: string // X.509 Certificate SHA1-Thumbprint
  x5u?: string // X.509 URL
}

/**
 * Registered Claim Names according to
 * RFC 7519 - JSON Web Token (JWT)
 *
 * [RFC7519](https://www.rfc-editor.org/rfc/rfc7519#section-4)
 */
export interface JWTClaims {
  aud?: string | string[] // Audience(s)
  exp?: number // Expiration Time
  iat?: number // Issued At
  iss?: string // Issuer
  jti?: string // JWT ID
  nbf?: number // Not Before
  sub?: string  // Subject
}

/**
 * Encodes a JSON object to base64url
 *
 * @param input - an arbitrary object that can be represented as JSON
 * @returns The base64url encoded version of the object
 */
export function jsonbase64url(input: Parameters<typeof JSON.stringify>[0]): string {
  return Buffer.from(JSON.stringify(input)).toString('base64url')
}

/**
 * Creates a string representation of header, payload and signature
 *
 * @remarks
 * According to RFC 7519 Section 6 an unsigned JWT will have the signature part
 * represented as an empty string.
 *
 * @param header - The header of the JWT token
 * @param payload - Claims that represent the payload of your JWT
 * @param signature - The signature of the token as a string. You can omit the parameter for unsigned tokens
 * @returns the encoded token
 */
export function joinJwt(header: JOSEHeader, payload: JWTClaims, signature?: string): string {
  return [
    jsonbase64url(header),
    jsonbase64url(payload),
    signature ? signature : ''
  ].join(".")
}

export class JWT<CustomClaims extends JWTClaims = JWTClaims> {
  header: JOSEHeader
  issuer: BaseIssuer
  payload: CustomClaims
  signature?: string

  constructor(issuer: BaseIssuer, header: JOSEHeader, payload: CustomClaims) {
    this.issuer = issuer
    this.header = header
    this.payload = payload
  }

  becomesValidInSeconds(seconds: number): this {
    this.payload.nbf = Math.floor(Date.now() / 1000 + seconds)
    return this
  }

  expireAt(exp: number): this {
    this.payload.exp = exp
    return this
  }

  expireInSeconds(seconds: number): this {
    this.payload.exp = Math.floor(Date.now() / 1000 + seconds)
    return this
  }

  expireNow(): this {
    return this.expireInSeconds(0)
  }

  expired(): this {
    return this.expireInSeconds(-60)
  }

  prettyPrint(includeSignature: boolean = false): string {
    const signature = this.signature ? includeSignature ? this.signature : '[Signature]' : '[No Signature]'
    return [
      JSON.stringify(this.header, undefined, 2),
      JSON.stringify(this.payload, undefined, 2),
      signature
    ].join(".")
  }

  sign(): this {
    const signature = this.issuer.sign(this)
    if (signature) {
      this.signature = signature
    }
    return this
  }

  toString(): string {
    if (!this.signature) {
      return joinJwt(this.header, this.payload)
    }
    return joinJwt(this.header, this.payload, this.signature)
  }

  unknownKid(): this {
    this.header.kid = randomBytes(20).toString('hex')
    return this
  }

  updateClaims(claims: Partial<CustomClaims>): this {
    Object.assign(this.payload, claims)
    return this
  }

  updateHeader(header: Partial<JOSEHeader>): this {
    Object.assign(this.header, header)
    return this
  }

  withAudience(aud: NonNullable<CustomClaims["aud"]>): this {
    this.payload.aud = aud
    return this
  }

  withIssuer(iss: NonNullable<CustomClaims["iss"]>): this {
    this.payload.iss = iss
    return this
  }

  withSubject(sub: NonNullable<CustomClaims["sub"]>): this {
    this.payload.sub = sub
    return this
  }
}
