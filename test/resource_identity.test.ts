import test from 'node:test'
import assert from 'node:assert/strict'
import { captureRejection } from './_errors.js'

import * as jose from 'jose'
import * as lib from './_lib.js'

const now = () => Math.floor(Date.now() / 1000)

const issuer = 'https://as.example.com'
const resource = 'https://rs.example.com'

async function setup(claims: Record<string, unknown> = {}) {
  // A fresh Authorization Server object per setup so that the module's JWKS cache (keyed on the
  // metadata object identity) never serves another test's keys.
  const as: lib.AuthorizationServer = {
    issuer,
    jwks_uri: 'https://as.example.com/jwks',
  }
  const asKey = await lib.generateKeyPair('ES256', { extractable: true })
  const publicJwk = await jose.exportJWK(asKey.publicKey)
  const iat = now()
  const accessToken = await new jose.SignJWT({
    iss: issuer,
    exp: iat + 300,
    aud: resource,
    sub: 'sub',
    iat,
    jti: 'jti',
    client_id: 'client_id',
    ...claims,
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt' })
    .sign(asKey.privateKey)

  const options: lib.ValidateJWTAccessTokenOptions = {
    [lib.customFetch]: async () =>
      new Response(JSON.stringify({ keys: [publicJwk] }), {
        headers: { 'content-type': 'application/json' },
      }),
  }

  const request = (url = `${resource}/resource?query`) =>
    new Request(url, { headers: { authorization: `Bearer ${accessToken}` } })

  return { as, accessToken, options, request }
}

test('validateResourceIdentity() returns a traceable resource identity', async () => {
  const { as, options, request } = await setup()

  const identity = await lib.validateResourceIdentity(as, { resource }, request(), options)

  assert.strictEqual(identity.issuer, issuer)
  assert.strictEqual(identity.audience, resource)
  assert.strictEqual(identity.endpoint, `${resource}/resource`)
  assert.strictEqual(identity.claims.iss, issuer)
  assert.strictEqual(identity.claims.sub, 'sub')
})

test('validateResourceIdentity() accepts an issuer from authorization_servers', async () => {
  const { as, options, request } = await setup()

  const identity = await lib.validateResourceIdentity(
    as,
    { resource, authorization_servers: [issuer] },
    request(),
    options,
  )

  assert.strictEqual(identity.issuer, issuer)
})

test('validateResourceIdentity() rejects an issuer missing from authorization_servers', async () => {
  const { as, options, request } = await setup()

  const err = await captureRejection(
    lib.validateResourceIdentity(
      as,
      { resource, authorization_servers: ['https://another-as.example.com'] },
      request(),
      options,
    ),
    (error) => {
      assert.ok(error instanceof lib.OperationProcessingError)
      assert.strictEqual(
        error.message,
        'authorization server issuer is not one of the resource metadata "authorization_servers"',
      )
      return true
    },
  )

  assert.strictEqual(err?.code, lib.JSON_ATTRIBUTE_COMPARISON)
})

test('validateResourceIdentity() rejects an unexpected token issuer', async () => {
  const { as, options, request } = await setup({ iss: 'https://another-as.example.com' })

  const err = await captureRejection(
    lib.validateResourceIdentity(as, { resource }, request(), options),
    (error) => {
      assert.ok(error instanceof lib.OperationProcessingError)
      assert.strictEqual(error.message, 'unexpected JWT "iss" (issuer) claim value')
      return true
    },
  )

  assert.strictEqual(err?.code, lib.JWT_CLAIM_COMPARISON)
})

test('validateResourceIdentity() rejects an unexpected token audience', async () => {
  const { as, options, request } = await setup({ aud: 'https://another-rs.example.com' })

  const err = await captureRejection(
    lib.validateResourceIdentity(as, { resource }, request(), options),
    (error) => {
      assert.ok(error instanceof lib.OperationProcessingError)
      assert.strictEqual(error.message, 'unexpected JWT "aud" (audience) claim value')
      return true
    },
  )

  assert.strictEqual(err?.code, lib.JWT_CLAIM_COMPARISON)
})

test('validateResourceIdentity() rejects a token replayed at another origin', async () => {
  const { as, options, request } = await setup()

  const err = await captureRejection(
    lib.validateResourceIdentity(
      as,
      { resource },
      request('https://another-rs.example.com/resource'),
      options,
    ),
    (error) => {
      assert.ok(error instanceof lib.OperationProcessingError)
      assert.strictEqual(error.message, 'request URL does not match the resource identifier')
      return true
    },
  )

  assert.strictEqual(err?.code, lib.INVALID_REQUEST)
})

test('validateResourceIdentity() binds path-scoped resource identifiers', async () => {
  const scoped = `${resource}/api`
  const { as, options, request } = await setup({ aud: scoped })
  const metadata = { resource: scoped }

  const identity = await lib.validateResourceIdentity(
    as,
    metadata,
    request(`${scoped}/users`),
    options,
  )
  assert.strictEqual(identity.audience, scoped)

  for (const url of [`${resource}/other`, `${resource}/apis`]) {
    const err = await captureRejection(
      lib.validateResourceIdentity(as, metadata, request(url), options),
      (error) => {
        assert.ok(error instanceof lib.OperationProcessingError)
        assert.strictEqual(error.message, 'request URL does not match the resource identifier')
        return true
      },
    )

    assert.strictEqual(err?.code, lib.INVALID_REQUEST)
  }
})

test('validateResourceIdentity() supports multiple resource identifiers', async () => {
  const other = 'https://rs2.example.com'
  const { as, options, request } = await setup({ aud: [resource, other] })
  const metadata = [{ resource }, { resource: other }]

  const identity = await lib.validateResourceIdentity(
    as,
    metadata,
    request(`${other}/resource`),
    options,
  )
  assert.strictEqual(identity.audience, other)
  assert.strictEqual(identity.endpoint, `${other}/resource`)

  // A token only issued for another of the resource server's identifiers is rejected
  const { as: as2, options: options2, request: request2 } = await setup({ aud: resource })
  const err = await captureRejection(
    lib.validateResourceIdentity(as2, metadata, request2(`${other}/resource`), options2),
    (error) => {
      assert.ok(error instanceof lib.OperationProcessingError)
      assert.strictEqual(error.message, 'unexpected JWT "aud" (audience) claim value')
      return true
    },
  )

  assert.strictEqual(err?.code, lib.JWT_CLAIM_COMPARISON)
})

test('validateResourceIdentity() input validation', async () => {
  const { as, options, request } = await setup()

  await assert.rejects(lib.validateResourceIdentity(as, [], request(), options), {
    message: '"resource" must not be an empty array',
  })
  await assert.rejects(
    lib.validateResourceIdentity(as, {} as lib.ResourceServer, request(), options),
    { message: '"resource.resource" must be a string' },
  )
  await assert.rejects(lib.validateResourceIdentity(as, { resource: 'foo' }, request(), options), {
    message: '"resource.resource" must be a valid URL',
  })
  await assert.rejects(
    lib.validateResourceIdentity(as, [{ resource }, {} as lib.ResourceServer], request(), options),
    { message: '"resource[1].resource" must be a string' },
  )
  await assert.rejects(
    lib.validateResourceIdentity(as, { resource }, null as unknown as Request, options),
    { message: '"request" must be an instance of Request' },
  )
})

test('validateJwtAccessToken() accepts multiple expected audiences', async () => {
  const { as, options, request } = await setup()

  const claims = await lib.validateJwtAccessToken(
    as,
    request(),
    ['https://rs1.example.com', resource],
    options,
  )
  assert.strictEqual(claims.sub, 'sub')

  const err = await captureRejection(
    lib.validateJwtAccessToken(as, request(), ['https://rs1.example.com'], options),
    (error) => {
      assert.ok(error instanceof lib.OperationProcessingError)
      assert.strictEqual(error.message, 'unexpected JWT "aud" (audience) claim value')
      return true
    },
  )

  assert.strictEqual(err?.code, lib.JWT_CLAIM_COMPARISON)

  await assert.rejects(lib.validateJwtAccessToken(as, request(), [], options), {
    message: '"expectedAudience" must not be an empty array',
  })
})
