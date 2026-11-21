import test, { before, after } from 'node:test'
import assert from 'node:assert/strict'
import * as crypto from 'node:crypto'
import setup, { type Context, teardown, client } from './_setup.js'
import * as jose from 'jose'
import * as lib from './_lib.js'

const context = {} as Context

before(() => setup(context))
after(() => teardown(context))

const sha256 = (value: string) => crypto.createHash('sha256').update(value).digest('base64url')

type ProofClaims = {
  iat: number
  jti: string
  htm: string
  htu: string
  nonce?: string
  ath?: string
}

type FetchInit = NonNullable<
  Parameters<NonNullable<lib.HttpRequestOptions<string, unknown>[typeof lib.customFetch]>>[1]
>

const proofFromInit = (init: FetchInit): { dpop: string; claims: ProofClaims } => {
  const dpop = new Headers(init.headers).get('dpop')!
  assert.ok(dpop, 'request must carry a DPoP proof header')
  return { dpop, claims: jose.decodeJwt(dpop) as unknown as ProofClaims }
}

const nonceChallenge = (nonce: string) =>
  new Response(null, {
    status: 401,
    headers: {
      'www-authenticate': 'DPoP error="use_dpop_nonce"',
      'dpop-nonce': nonce,
    },
  })

const requestOnce = (
  DPoP: lib.DPoPHandle,
  url: URL,
  accessToken: string,
  method: string,
  observer: (init: FetchInit) => Response,
) =>
  lib.protectedResourceRequest(accessToken, method, url, undefined, undefined, {
    DPoP,
    [lib.customFetch]: async (_url, init) => observer(init),
  })

test('plain Bearer request without a DPoP handle stays a Bearer request', async () => {
  const url = new URL('https://rs.example.com/bearer')
  const response = await lib.protectedResourceRequest('token', 'GET', url, undefined, undefined, {
    [lib.customFetch]: async (_url, init) => {
      const headers = new Headers(init.headers)
      assert.strictEqual(headers.get('authorization'), 'Bearer token')
      assert.strictEqual(headers.get('dpop'), null)
      return new Response()
    },
  })

  assert.strictEqual(response.status, 200)
})

test('legitimate nonce retry keeps every proof bound to that one request', async () => {
  const DPoP = lib.DPoP(client, await lib.generateKeyPair('ES256'))
  const url = new URL('https://rs.example.com/retry?foo=1#frag')
  const seen: ProofClaims[] = []
  let requests = 0

  const run = () =>
    requestOnce(DPoP, url, 'access-token', 'GET', (init) => {
      seen.push(proofFromInit(init).claims)
      if (++requests === 1) {
        return nonceChallenge('rotated-nonce')
      }
      return new Response()
    })

  const response = await run().catch((error) => {
    assert.strictEqual(lib.isDPoPNonceError(error), true)
    return run()
  })

  assert.strictEqual(response.status, 200)
  assert.strictEqual(requests, 2)

  const [first, retried] = seen

  assert.strictEqual(first.nonce, undefined)
  assert.strictEqual(retried.nonce, 'rotated-nonce')

  for (const claims of seen) {
    assert.strictEqual(claims.htm, 'GET')
    assert.strictEqual(claims.htu, 'https://rs.example.com/retry')
    assert.strictEqual(claims.ath, sha256('access-token'))
    assert.strictEqual(typeof claims.jti, 'string')
    assert.strictEqual(claims.jti.length > 0, true)
  }

  assert.notStrictEqual(first.jti, retried.jti)
})

test('nonce rotation: a newer server nonce replaces the cached one on the following request', async () => {
  const DPoP = lib.DPoP(client, await lib.generateKeyPair('ES256'))
  const url = new URL('https://rs.example.com/nonce-rotation')
  const nonces: Array<string | undefined> = []
  let requests = 0

  const run = () =>
    requestOnce(DPoP, url, 'token', 'POST', (init) => {
      nonces.push(proofFromInit(init).claims.nonce)
      if (++requests === 1) {
        return nonceChallenge('first-nonce')
      }
      if (requests === 2) {
        return nonceChallenge('second-nonce')
      }
      return new Response()
    })

  for (;;) {
    try {
      await run()
      break
    } catch (error) {
      assert.strictEqual(lib.isDPoPNonceError(error), true)
    }
  }

  assert.deepStrictEqual(nonces, [undefined, 'first-nonce', 'second-nonce'])

  const proof = proofFromInit
  await requestOnce(DPoP, url, 'token', 'POST', (init) => {
    assert.strictEqual(proof(init).claims.nonce, 'second-nonce')
    return new Response()
  })
})

test('repeated jti: every proof gets a unique jti, including retries and repeated calls', async () => {
  const DPoP = lib.DPoP(client, await lib.generateKeyPair('ES256'))
  const url = new URL('https://rs.example.com/jti')
  const jtis: string[] = []

  for (let i = 0; i < 3; i += 1) {
    await requestOnce(DPoP, url, 'token', 'GET', (init) => {
      jtis.push(proofFromInit(init).claims.jti)
      return new Response()
    })
  }

  let requests = 0
  const retry = () =>
    requestOnce(DPoP, url, 'token', 'GET', (init) => {
      jtis.push(proofFromInit(init).claims.jti)
      if (++requests === 1) {
        return nonceChallenge('nonce-for-jti')
      }
      return new Response()
    })

  await retry().catch((error) => {
    assert.strictEqual(lib.isDPoPNonceError(error), true)
    return retry()
  })

  assert.strictEqual(jtis.length, new Set(jtis).size)
})

test('wrong target: proofs never cross origins or paths and nonces stay origin-scoped', async () => {
  const DPoP = lib.DPoP(client, await lib.generateKeyPair('ES256'))
  const firstTarget = new URL('https://rs-a.example.com/path-a')
  const secondTarget = new URL('https://rs-b.example.com/path-b')

  await requestOnce(DPoP, firstTarget, 'token-a', 'GET', (init) => {
    const { claims } = proofFromInit(init)
    assert.strictEqual(claims.htu, 'https://rs-a.example.com/path-a')
    assert.strictEqual(claims.htm, 'GET')
    assert.strictEqual(claims.ath, sha256('token-a'))
    return nonceChallenge('nonce-for-a')
  }).catch((error) => {
    assert.strictEqual(lib.isDPoPNonceError(error), true)
  })

  await requestOnce(DPoP, secondTarget, 'token-b', 'PUT', (init) => {
    const { claims } = proofFromInit(init)
    assert.strictEqual(claims.htu, 'https://rs-b.example.com/path-b')
    assert.strictEqual(claims.htm, 'PUT')
    assert.strictEqual(claims.ath, sha256('token-b'))
    assert.strictEqual(claims.nonce, undefined)
    return new Response()
  })

  await requestOnce(DPoP, firstTarget, 'token-a', 'GET', (init) => {
    const { claims } = proofFromInit(init)
    assert.strictEqual(claims.htu, 'https://rs-a.example.com/path-a')
    assert.strictEqual(claims.nonce, 'nonce-for-a')
    return new Response()
  })
})

test('non-challenge responses do not replay or reuse a proof', async () => {
  const DPoP = lib.DPoP(client, await lib.generateKeyPair('ES256'))
  const url = new URL('https://rs.example.com/no-challenge')
  const dpopHeaders: string[] = []

  for (const status of [200, 403, 500]) {
    await requestOnce(DPoP, url, 'token', 'GET', (init) => {
      dpopHeaders.push(new Headers(init.headers).get('dpop')!)
      return new Response(null, { status })
    }).catch(() => {})
  }

  assert.strictEqual(dpopHeaders.length, 3)
  assert.strictEqual(new Set(dpopHeaders).size, 3)
})

test('non-challenge errors are not treated as nonce errors', async () => {
  const url = new URL('https://rs.example.com/challenges')
  const error = await assert.rejects(
    lib.protectedResourceRequest('token', 'GET', url, undefined, undefined, {
      [lib.customFetch]: async () =>
        new Response(null, {
          status: 401,
          headers: { 'www-authenticate': 'DPoP error="invalid_dpop_proof"' },
        }),
    }),
    lib.WWWAuthenticateChallengeError,
  )

  assert.strictEqual(lib.isDPoPNonceError(error), false)
})
