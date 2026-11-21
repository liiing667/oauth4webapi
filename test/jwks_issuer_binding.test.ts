import test, { before, after } from 'node:test'
import assert from 'node:assert/strict'

import * as jose from 'jose'
import setup, { client, getResponse, teardown, type Context } from './_setup.js'
import * as lib from './_lib.js'

const context = {} as Context

before(() => setup(context))
after(() => teardown(context))

function authorizationServer(origin: string): lib.AuthorizationServer {
  return {
    issuer: origin,
    jwks_uri: `${origin}/jwks`,
    authorization_signing_alg_values_supported: ['ES256'],
  }
}

function sign(privateKey: CryptoKey, iss: string, header: Record<string, string> = {}) {
  return new jose.SignJWT({})
    .setProtectedHeader({ alg: 'ES256', ...header })
    .setAudience(client.client_id)
    .setIssuer(iss)
    .setExpirationTime('10m')
    .sign(privateKey)
}

function validate(as: lib.AuthorizationServer, jwt: string, options: lib.ValidateSignatureOptions) {
  return lib.validateJwtAuthResponse(
    as,
    client,
    new URLSearchParams({ response: jwt }),
    undefined,
    options,
  )
}

test('a JWKS cache recorded for another issuer is not used', async () => {
  const keyA = await lib.generateKeyPair('ES256', { extractable: true })
  const keyB = await lib.generateKeyPair('ES256', { extractable: true })
  const asA = authorizationServer('https://a.example.com')
  const asB = authorizationServer('https://b.example.com')
  const jwksA = { keys: [{ ...(await jose.exportJWK(keyA.publicKey)), kid: 'shared' }] }
  const jwksB = { keys: [{ ...(await jose.exportJWK(keyB.publicKey)), kid: 'shared' }] }

  const requests: string[] = []
  const fetchJwks: lib.ValidateSignatureOptions[typeof lib.customFetch] = async (url) => {
    requests.push(`${url}`)
    if (`${url}` === asA.jwks_uri) {
      return getResponse(JSON.stringify(jwksA))
    }
    if (`${url}` === asB.jwks_uri) {
      return getResponse(JSON.stringify(jwksB))
    }
    throw new Error('unexpected request')
  }

  // a single cache object reused across issuers, as a persisted cache would be
  const cache: lib.JWKSCacheInput = {}
  const options: lib.ValidateSignatureOptions = {
    [lib.customFetch]: fetchJwks,
    [lib.jwksCache]: cache,
  }

  // populates the shared cache with issuer A's JWKS
  await validate(asA, await sign(keyA.privateKey, asA.issuer, { kid: 'shared' }), options)
  assert.deepStrictEqual(requests, [asA.jwks_uri])
  assert.strictEqual(cache.issuer, asA.issuer)

  // a JWT for issuer B signed with issuer A's key must not verify against issuer A's
  // cached keys even though the "kid" matches
  const forged = await sign(keyA.privateKey, asB.issuer, { kid: 'shared' })
  await assert.rejects(validate(asB, forged, options), {
    message: 'JWT signature verification failed',
  })

  // the mismatched cache was discarded and issuer B's JWKS was fetched instead
  assert.deepStrictEqual(requests, [asA.jwks_uri, asB.jwks_uri])
  assert.strictEqual(cache.issuer, asB.issuer)

  // a genuine issuer B JWT verifies against the refreshed cache
  await validate(asB, await sign(keyB.privateKey, asB.issuer, { kid: 'shared' }), options)
  assert.deepStrictEqual(requests, [asA.jwks_uri, asB.jwks_uri])
})

test('caches recorded before issuer binding are still accepted', async () => {
  const keyPair = await lib.generateKeyPair('ES256', { extractable: true })
  const as = authorizationServer('https://legacy.example.com')
  const cache: lib.ExportedJWKSCache = {
    uat: Math.floor(Date.now() / 1000),
    jwks: { keys: [await jose.exportJWK(keyPair.publicKey)] },
  }

  let requests = 0
  await validate(as, await sign(keyPair.privateKey, as.issuer), {
    [lib.customFetch]: async () => {
      requests++
      return getResponse(JSON.stringify({ keys: [] }))
    },
    [lib.jwksCache]: cache,
  })
  assert.strictEqual(requests, 0)
})

test('keys are selected using the JWT header alg and key use, not just the kid', async () => {
  const keyPair = await lib.generateKeyPair('ES256', { extractable: true })
  const jwk = { ...(await jose.exportJWK(keyPair.publicKey)), kid: 'one' }
  const jwt = await sign(keyPair.privateKey, 'https://selector.example.com', { kid: 'one' })

  // a legacy JWKS whose keys don't declare alg/use remains usable
  await validate(authorizationServer('https://selector.example.com'), jwt, {
    [lib.customFetch]: async () => getResponse(JSON.stringify({ keys: [jwk] })),
  })

  // a JWK declaring a different alg is not selected
  await assert.rejects(
    validate(authorizationServer('https://selector.example.com'), jwt, {
      [lib.customFetch]: async () =>
        getResponse(JSON.stringify({ keys: [{ ...jwk, alg: 'ES384' }] })),
    }),
    { message: 'error when selecting a JWT verification key, no applicable keys found' },
  )

  // a JWK declaring a non-signature use is not selected
  await assert.rejects(
    validate(authorizationServer('https://selector.example.com'), jwt, {
      [lib.customFetch]: async () =>
        getResponse(JSON.stringify({ keys: [{ ...jwk, use: 'enc' }] })),
    }),
    { message: 'error when selecting a JWT verification key, no applicable keys found' },
  )
})

test('multiple applicable keys with the same kid are rejected', async () => {
  const keyA = await lib.generateKeyPair('ES256', { extractable: true })
  const keyB = await lib.generateKeyPair('ES256', { extractable: true })
  const as = authorizationServer('https://duplicate.example.com')
  const jwks = {
    keys: [
      { ...(await jose.exportJWK(keyA.publicKey)), kid: 'dup' },
      { ...(await jose.exportJWK(keyB.publicKey)), kid: 'dup' },
    ],
  }
  const jwt = await sign(keyA.privateKey, as.issuer, { kid: 'dup' })

  await assert.rejects(
    validate(as, jwt, {
      [lib.customFetch]: async () => getResponse(JSON.stringify(jwks)),
    }),
    {
      message:
        'error when selecting a JWT verification key, multiple applicable keys found, a "kid" JWT Header Parameter is required',
    },
  )
})
