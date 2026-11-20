import test, { before, after } from 'node:test'
import assert from 'node:assert/strict'
import { captureRejection } from './_errors.js'

import setup, {
  client,
  endpoint,
  issuer,
  setupContextKeys,
  teardown,
  type ContextWithAlgs,
} from './_setup.js'
import * as jose from 'jose'
import * as lib from './_lib.js'

const context = {} as ContextWithAlgs

before(() => setup(context))
after(() => teardown(context))
before(() => setupContextKeys(context))

test('client_secret_basic', async () => {
  context
    .intercept({
      path: '/test-basic',
      method: 'POST',
      headers: {
        authorization: (header) => header.startsWith('Basic '),
      },
      body(body) {
        const params = new URLSearchParams(body)
        return !params.has('client_id') && !params.has('client_secret')
      },
    })
    .reply(200, '')

  await lib.revocationRequest(
    { ...issuer, revocation_endpoint: endpoint('test-basic') },
    client,
    lib.ClientSecretBasic('foo'),
    'token',
  )
})

test('client_secret_basic (appendix b)', async () => {
  context
    .intercept({
      path: '/test-basic-encoding',
      method: 'POST',
      headers: {
        authorization(authorization) {
          const [, auth] = authorization.split(' ')
          for (const token of atob(auth).split(':')) {
            assert.strictEqual(/[^a-zA-Z0-9%+]/.test(token), false)
            assert.deepStrictEqual(token, 'client+%25%26%2B%2D%5F%2E%21%7E%2A%27%28%29')
          }
          return true
        },
      },
      body(body) {
        const params = new URLSearchParams(body)
        return !params.has('client_id') && !params.has('client_secret')
      },
    })
    .reply(200, '')

  await lib.revocationRequest(
    { ...issuer, revocation_endpoint: endpoint('test-basic-encoding') },
    {
      ...client,
      client_id: "client %&+-_.!~*'()",
    },
    lib.ClientSecretBasic("client %&+-_.!~*'()"),
    'token',
  )
})

test('client_secret_post', async () => {
  context
    .intercept({
      path: '/test-post',
      method: 'POST',
      headers(headers) {
        return !('authorization' in headers)
      },
      body(body) {
        const params = new URLSearchParams(body)
        return params.get('client_id') === client.client_id && params.get('client_secret') === 'foo'
      },
    })
    .reply(200, '')

  await lib.revocationRequest(
    { ...issuer, revocation_endpoint: endpoint('test-post') },
    client,
    lib.ClientSecretPost('foo'),
    'token',
  )
})

test('private_key_jwt', async () => {
  const tIssuer = {
    ...issuer,
    revocation_endpoint: endpoint('test-pkjwt-1'),
    token_endpoint: endpoint('token'),
  }

  context
    .intercept({
      path: '/test-pkjwt-1',
      method: 'POST',
      headers(headers) {
        return !('authorization' in headers)
      },
      body(body) {
        const params = new URLSearchParams(body)
        assert.strictEqual(params.has('client_secret'), false)
        assert.strictEqual(params.has('client_assertion'), true)
        assert.strictEqual(params.get('client_id'), client.client_id)
        assert.strictEqual(
          params.get('client_assertion_type'),
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        )

        const assertion = jose.decodeJwt(params.get('client_assertion')!)
        assert.strictEqual(assertion.aud, tIssuer.issuer)
        assert.strictEqual(assertion.iss, client.client_id)
        assert.strictEqual(assertion.sub, client.client_id)
        assert.strictEqual(typeof assertion.exp, 'number')
        assert.strictEqual(typeof assertion.iat, 'number')
        assert.strictEqual(typeof assertion.nbf, 'number')
        assert.strictEqual(typeof assertion.jti, 'string')
        const header = jose.decodeProtectedHeader(params.get('client_assertion')!)
        assert.strictEqual(header.kid, undefined)

        return true
      },
    })
    .reply(200, '')
    .times(2)

  await lib.revocationRequest(
    tIssuer,
    client,
    lib.PrivateKeyJwt({ key: context.ES256.privateKey }),
    'token',
  )
  await lib.revocationRequest(tIssuer, client, lib.PrivateKeyJwt(context.ES256.privateKey), 'token')
  assert.throws(() => lib.PrivateKeyJwt({ key: context.ES256.publicKey }), {
    message: '"clientPrivateKey.key" must be a private CryptoKey',
  })
  assert.throws(() => lib.PrivateKeyJwt({ key: null as any }), {
    message: '"clientPrivateKey.key" must be a CryptoKey',
  })
})

test('private_key_jwt ({ key: CryptoKey, kid: string })', async () => {
  const tIssuer = {
    ...issuer,
    revocation_endpoint: endpoint('test-pkjwt-2'),
    token_endpoint: endpoint('token'),
  }

  context
    .intercept({
      path: '/test-pkjwt-2',
      method: 'POST',
      headers(headers) {
        return !('authorization' in headers)
      },
      body(body) {
        const params = new URLSearchParams(body)
        assert.strictEqual(params.has('client_secret'), false)
        assert.strictEqual(params.has('client_assertion'), true)
        assert.strictEqual(params.get('client_id'), client.client_id)
        assert.strictEqual(
          params.get('client_assertion_type'),
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        )

        const assertion = jose.decodeJwt(params.get('client_assertion')!)
        assert.strictEqual(assertion.aud, tIssuer.issuer)
        assert.strictEqual(assertion.iss, client.client_id)
        assert.strictEqual(assertion.sub, client.client_id)
        assert.strictEqual(typeof assertion.exp, 'number')
        assert.strictEqual(typeof assertion.iat, 'number')
        assert.strictEqual(typeof assertion.nbf, 'number')
        assert.strictEqual(typeof assertion.jti, 'string')
        const header = jose.decodeProtectedHeader(params.get('client_assertion')!)
        assert.strictEqual(header.kid, 'keyId')

        return true
      },
    })
    .reply(200, '')

  await lib.revocationRequest(
    tIssuer,
    client,
    lib.PrivateKeyJwt({ key: context.ES256.privateKey, kid: 'keyId' }),
    'token',
  )
  assert.throws(() => lib.PrivateKeyJwt({ key: context.ES256.publicKey, kid: 'keyId' }), {
    message: '"clientPrivateKey.key" must be a private CryptoKey',
  })
  assert.throws(() => lib.PrivateKeyJwt({ key: context.ES256.publicKey, kid: 123 as any }), {
    message: '"kid" must be a string',
  })
})

test('none', async () => {
  context
    .intercept({
      path: '/test-none',
      method: 'POST',
      headers(headers) {
        return !('authorization' in headers)
      },
      body(body) {
        const params = new URLSearchParams(body)
        return params.has('client_id') && !params.has('client_secret')
      },
    })
    .reply(200, '')

  await lib.revocationRequest(
    { ...issuer, revocation_endpoint: endpoint('test-none') },
    client,
    lib.None(),
    'token',
  )
})

test('client_secret_jwt', async () => {
  const tIssuer = {
    ...issuer,
    revocation_endpoint: endpoint('test-csjwt-1'),
    token_endpoint: endpoint('token'),
  }

  context
    .intercept({
      path: '/test-csjwt-1',
      method: 'POST',
      headers(headers) {
        return !('authorization' in headers)
      },
      body(body) {
        const params = new URLSearchParams(body)
        assert.strictEqual(params.has('client_secret'), false)
        assert.strictEqual(params.has('client_assertion'), true)
        assert.strictEqual(params.get('client_id'), client.client_id)
        assert.strictEqual(
          params.get('client_assertion_type'),
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        )

        const assertion = jose.decodeJwt(params.get('client_assertion')!)
        assert.strictEqual(assertion.aud, tIssuer.issuer)
        assert.strictEqual(assertion.iss, client.client_id)
        assert.strictEqual(assertion.sub, client.client_id)
        assert.strictEqual(typeof assertion.exp, 'number')
        assert.strictEqual(typeof assertion.iat, 'number')
        assert.strictEqual(typeof assertion.nbf, 'number')
        assert.strictEqual(typeof assertion.jti, 'string')
        const header = jose.decodeProtectedHeader(params.get('client_assertion')!)
        assert.strictEqual(header.kid, undefined)
        assert.strictEqual(header.alg, 'HS256')

        return true
      },
    })
    .reply(200, '')

  await lib.revocationRequest(tIssuer, client, lib.ClientSecretJwt('client_secret'), 'token')
})

test('conflicting "authorization" header is rejected before the request', async () => {
  const tIssuer = {
    ...issuer,
    revocation_endpoint: endpoint('test-conflicting-header'),
  }

  await assert.rejects(
    lib.revocationRequest(tIssuer, client, lib.ClientSecretBasic('foo'), 'token', {
      headers: { authorization: 'Bearer unrelated' },
    }),
    {
      name: 'TypeError',
      code: 'ERR_INVALID_ARG_VALUE',
      message: '"options.headers" must not include the "authorization" header name',
    },
  )
})

test('conflicting form parameters are rejected before the request', async () => {
  const tIssuer = {
    ...issuer,
    revocation_endpoint: endpoint('test-conflicting-params'),
  }

  await assert.rejects(
    lib.revocationRequest(tIssuer, client, lib.ClientSecretBasic('foo'), 'token', {
      additionalParameters: { client_secret: 'bar' },
    }),
    {
      name: 'TypeError',
      code: 'ERR_INVALID_ARG_VALUE',
      message:
        '"client_secret_basic" client authentication cannot be combined with the "client_secret" request parameter',
    },
  )

  await assert.rejects(
    lib.revocationRequest(tIssuer, client, lib.None(), 'token', {
      additionalParameters: [
        ['client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'],
        ['client_assertion', 'eyJhbGciOiJub25lIn0.e30.'],
      ],
    }),
    {
      name: 'TypeError',
      code: 'ERR_INVALID_ARG_VALUE',
      message:
        '"none" client authentication cannot be combined with the "client_assertion", "client_assertion_type" request parameters',
    },
  )

  await assert.rejects(
    lib.revocationRequest(tIssuer, client, lib.ClientSecretPost('foo'), 'token', {
      additionalParameters: [['client_assertion', 'eyJhbGciOiJub25lIn0.e30.']],
    }),
    {
      name: 'TypeError',
      code: 'ERR_INVALID_ARG_VALUE',
      message:
        '"client_secret_post" client authentication cannot be combined with the "client_assertion" request parameter',
    },
  )

  await assert.rejects(
    lib.revocationRequest(tIssuer, client, lib.ClientSecretBasic('foo'), 'token', {
      additionalParameters: [
        ['client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'],
        ['client_assertion', 'eyJhbGciOiJub25lIn0.e30.'],
      ],
    }),
    {
      name: 'TypeError',
      code: 'ERR_INVALID_ARG_VALUE',
      message:
        '"client_secret_basic" client authentication cannot be combined with the "client_assertion", "client_assertion_type" request parameters',
    },
  )
})

test('duplicated client authentication parameters are rejected before the request', async () => {
  const tIssuer = {
    ...issuer,
    revocation_endpoint: endpoint('test-duplicated-params'),
  }

  await assert.rejects(
    lib.revocationRequest(tIssuer, client, lib.ClientSecretPost('foo'), 'token', {
      additionalParameters: [
        ['client_secret', 'bar'],
        ['client_secret', 'baz'],
      ],
    }),
    {
      name: 'TypeError',
      code: 'ERR_INVALID_ARG_VALUE',
      message: 'the "client_secret" request parameter must not be provided more than once',
    },
  )

  await assert.rejects(
    lib.revocationRequest(tIssuer, client, lib.None(), 'token', {
      additionalParameters: [
        ['client_id', 'other-client'],
        ['client_id', 'yet-another-client'],
      ],
    }),
    {
      name: 'TypeError',
      code: 'ERR_INVALID_ARG_VALUE',
      message: 'the "client_id" request parameter must not be provided more than once',
    },
  )
})

test('cross-endpoint redirects are rejected instead of following them', async () => {
  const tIssuer = {
    ...issuer,
    revocation_endpoint: endpoint('test-redirect'),
  }

  context
    .intercept({
      path: '/test-redirect',
      method: 'POST',
    })
    .reply(303, '', {
      headers: { location: endpoint('somewhere-else') },
    })

  const error = await captureRejection(
    lib.revocationRequest(tIssuer, client, lib.ClientSecretBasic('foo'), 'token'),
    { name: 'OperationProcessingError', code: lib.RESPONSE_IS_NOT_CONFORM },
  )
  assert.match(error.message, /redirect to a different endpoint/)
})

test('a redirect back to the same endpoint is not treated as a cross-endpoint redirect', async () => {
  const tIssuer = {
    ...issuer,
    revocation_endpoint: endpoint('test-same-endpoint-redirect'),
  }

  context
    .intercept({
      path: '/test-same-endpoint-redirect',
      method: 'POST',
    })
    .reply(303, '', {
      headers: { location: endpoint('test-same-endpoint-redirect') },
    })

  const response = await lib.revocationRequest(tIssuer, client, lib.None(), 'token')
  assert.strictEqual(response.status, 303)
})
