# JWT Test Helper

[![CI Status](https://github.com/stschulte/jwt-test-helper/workflows/CI/badge.svg)](https://github.com/stschulte/jwt-test-helper/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/stschulte/jwt-test-helper/badge.svg?branch=main)](https://coveralls.io/github/stschulte/jwt-test-helper?branch=main)
[![npm version](https://badge.fury.io/js/jwt-test-helper.svg)](https://badge.fury.io/js/jwt-test-helper)

As a developer we provide APIs to protected resources. A lot of APIs require
JSON Web Tokens for access and validating tokens correctly becomes vital.

No matter wether you use a library to validate your tokens (like 
[jsonwebtoken][jsonwebtoken] or [aws-jwt-verify][aws-jwt-verify]) or you have
written your own code, testing out different scenarios can be really hard.

Let's assume the following question: "Does my code reject tokens that
have a correct signature, but are already expired?"

The problem: How can you call your function with a valid token (a token
with a valid signature) when you cannot control the token issuer (e.g.
your EntraID/AzureAD Tenant, AWS Cognito, etc) and as a result cannot
sign a token yourself?

As a result you may only test the happy-path of your validation function
or you do not test it at all. But does your code accept a token that
specifies a signature of `none` and is not signed at all? You should
test that!

How does this library help? It can

- Allows you to easily create tokens with arbitrary header and payload
  or different properties (e.g. expired tokens, not-yet-valid tokens, etc)
- create a public/private key to sign different tokens
- mock HTTP calls against the JWKS endpoint of your token issuer so your
  code under test can validate the generated tokens correctly (your code under test
  can map the `kid` value of the fake tokens to actual signing keys)

## Installation

Installing the package is easy. Just run

```
npm install --save-dev jwt-test-helper
```

## Example

We first need a token validation function you want to test.

Let's assume you validate incoming API tokens with [jsonwebtoken][jsonwebtoken]
and you use [jwks-rsa][jwks-rsa] to fetch the public keys of your token
issuer.

While the token issuer does not really matter the below example
assumes you want to validete tokens against a specific
(non-existing) EntraID tenant with a tenant Id of
`bc060424-c7f9-46d9-b0df-41e1dc387823`.

```typescript
// validate.ts
import { decode, verify } from "jsonwebtoken";
import { JwksClient } from "jwks-rsa";

let jwksRsa: JwksClient;

async function getSigningKey(kid: string): Promise<string> {
  if (!jwksRsa) {
    jwksRsa = new JwksClient({
      cache: true,
      jwksUri: "https://login.microsoftonline.com/bc060424-c7f9-46d9-b0df-41e1dc387823/discovery/v2.0/keys",
      rateLimit: true
    });
  }
  const key = await jwksRsa.getSigningKey(kid)
  if ('rsaPublicKey' in key) {
    return key.rsaPublicKey
  }
  return key.publicKey
}

export async function validate(
  jwtToken: string,
  issuer: string,
  audience: string
) {
  const decodedToken = decode(jwtToken, { complete: true })
  if (!decodedToken) {
    throw new Error("Cannot parse JWT token");
  }

  const kid = decodedToken["header"]["kid"];
  if (!kid) {
    throw new Error("Missing key id of token. Unable to verify")
  }
  const jwk = await getSigningKey(kid);

  // Verify the JWT
  // This either rejects (JWT not valid), or resolves (JWT valid)
  const verificationOptions = {
    audience,
    issuer,
  };

  return new Promise((resolve, reject) =>
    verify(jwtToken, jwk, verificationOptions, (err, decoded) =>
      err ? reject(err) : resolve(decoded)
    )
  );
}
```

We can now run a test that emulates the EntraID tenant and test your `validate`
function against an expired token. In this example we'll use vitest as a testing
framework.

```typescript
// validate.test.ts
import nock from 'nock'
import { beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { Issuer } from 'jwt-test-helper'

// This  is the method we want to test
import { validate } from './validate.js'

let fakeIssuer: Issuer

describe("validate", () => {
  beforeAll(() => {
    fakeIssuer = new Issuer(
      "https://login.microsoftonline.com/bc060424-c7f9-46d9-b0df-41e1dc387823/discovery/v2.0/keys"
    )
    fakeIssuer.generateKey()
  })

  beforeEach(() => {
    nock.disableNetConnect()
    fakeIssuer.mockJwksUri()
    return (() => {
      nock.cleanAll()
      nock.enableNetConnect()
    })
  })

  it("should reject expired tokens", async () => {
    const jwt = fakeIssuer
      .createSampleJwt(
        {},
        {
          iss: 'https://login.microsoftonline.com/bc060424-c7f9-46d9-b0df-41e1dc387823/v2.0',
          aud: '6e74172b-be56-4843-9ff4-e66a39bb12e3'
        }
      )
      .expired()
      .sign()

    // The key is signed and has the correct audience and issuer, but
    // it should complain about an expired key
    const promise = validate(
      jwt.toString(),
      'https://login.microsoftonline.com/bc060424-c7f9-46d9-b0df-41e1dc387823/v2.0',
      "6e74172b-be56-4843-9ff4-e66a39bb12e3",
    )

    await expect(promise).rejects.toThrow(/jwt expired/)
  })
})
```

## Usage

This library helps with two steps:

- Emulate a token issuer (e.g. create signing keys, mocking the JWKS endpoint
  to present the signing keys)
- Create JWT Tokens from the emulated token issuer with arbitrary content
  and possibly sign them

### Emulate a token issuer

The first thing we have to do is emulate the token issuer that you actually
use in your code (or emulate another token issuer to test out scenarios
wether you reject valid tokens that come from unexpected token issuers)

The following issuer represents an EntraID V2 token issuer but you can
emulate any token issuer that uses RSA keys to sign tokens.

```ts
import { Issuer } from 'jwt-test-helper'
const fakeIssuer = new Issuer("https://login.microsoftonline.com/bc060424-c7f9-46d9-b0df-41e1dc387823/discovery/v2.0/keys")
```

For some issuers there are more specific subclasses. This allows to more
accurately emulate them, e.g. some issuers use specific JWT claims or
include more data in the JWK endpoint.

```ts
import { EntraIdIssuer, EntraIdV2Issuer } from 'jwt-test-helper/issuer/entraid.js'

// The entra id issuer takes a tenantId and generates the jwkUrl
const fakeIssuer = new EntraIdIssuer("bc060424-c7f9-46d9-b0df-41e1dc387823")

// If your code uses the v2.0 endpoint, use an EntraIDV2 issuer instead
const fakeIssuer = new EntraIdV2Issuer("bc060424-c7f9-46d9-b0df-41e1dc387823")
```

One you have a fake token issuer you can generate a keypair. The issuer will
automatically generate a key Id for the new key. A token can reference the
key Id later with a `kid` header.

```ts
fakeIssuer.generateKey() // New key with generated KID
fakeIssuer.generateKey("KEYFOO") // Force a key id of KEYFOO

// Retrieve the KID of the first key
const kid = fakeIssuer.kid()

// Return the KID of a specific key
const kid = fakeIssuer.kid(1) // returns the kid of the second key
```

While the new key can be used to sign tokens, we also have to ensure
your code under test talks to your fake issuer to map a `kid` of an
incoming token to a public key of the fake issuer.

We do this by mocking calls to the JWK endpoint to the original issuer.
We assume your code will use the JWK endpoint of your token provider to
fetch public keys)

```ts
// validate.test.ts

import nock from 'nock' // you have to install nock

// Ensure we don't call any real endpoint
nock.disableNetConnect()

// Mock calls to the Jwks endpoint
fakeIssuer.mockJwksUri()

// Later: Enable network connections again
nock.enableNetConnect()
```

### Create tokens

Now lets create a valid token with a `kid` that matches a previously
generated key. The fake issuer will use the `kid` when you run the
`sign()` method. We have two ways to create a token with header and
payload: `createJwt` will create a token with the provided header and
payload. The method `createSampleJwt()` creates a token with some
predefined values. The issuer subclasses (e.g. `EntraIdIssuer`) also
overwrite `createSampleJwt()` so include standard claims of the more
specific issuer.

```ts
// The sample JWT will have a kid of the first generated keypair
// and an alg of RS256
const validToken = fakeIssuer
  .createJwt(
    {
      alg: 'RS256',
      kid: fakeIssuer.kid(0),
    },
    {
      sub: 'Bob'
    }
  )

// The above can also be written as
const validToken = fakeIssuer.createSampleJwt()
```

#### Create a signed token

You can run `sign()` on your token to add a signature based
on the current header and payload

```ts
const validToken = fakeIssuer.createSampleJwt().sign()
```

#### Create tampered token

If we sign a token and later change the header or payload the
token should be rejected by your code since the signature will no
longer match:

```ts
// Simulate a subject change from Alice to Bob
const tamperedToken = fakeIssuer
  .createSampleJwt()
  .updateClaims({"sub": "Alice"})
  .sign()
  .updateClaims({"sub": "Bob"})
```

#### Create an expired token

Or create an expired token or a token with a not-before-time in the future:

```ts
const expiredToken = fakeIssuer.createSampleJwt().expired().sign()
const invalidToken = fakeIssuer.createSampleJwt().becomesValidInSecond(10).sign()
```

#### Create an unsigned token

We can also create unsigned tokens with an algorithm of `none`. In general
your code should reject tokens specifying this algorithm. We can also create
a token that should have a signature (`alg` of `RS256` is the default) but
is still not signed:

```ts
const missingSignature = fakeIssuer.createSampleJwt({"sub": "Alice"})
const unsignedToken = fakeIssuer.createSampleJwt({alg: "none"}, {"sub": "Alice"})
```

#### Convert Token to a string

Once we are happy with our token properties we can transform it to a JWT
string we can pass to our validate function.

You can also use `prettyPrint()` to print the content of the JWT in human
readable form.

```ts
console.log(expiredToken.prettyPrint())
const jwt = expiredToken.toString()
```

For a full example look into the above Example section.

### Enhance Issuer

You may have an issuer that serves specific fields in the JWK endpoint that
you want to mimic as well. Or you want to change what a sample JWT looks
like. This can be creating a subclass of `BaseIssuer`.


[jsonwebtoken]: https://www.npmjs.com/package/jsonwebtoken
[jwks-rsa]: https://www.npmjs.com/package/jwks-rsa
[aws-jwt-verify]: https://www.npmjs.com/package/aws-jwt-verify
