import test from 'node:test'
import assert from 'node:assert/strict'

import * as jose from 'jose'
import * as lib from './_lib.js'
import { mangleJwtSignature } from './_tools.js'

const encoder = new TextEncoder()

async function accessTokenHash(accessToken: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(accessToken))
  return Buffer.from(digest).toString('base64url')
}

interface PreparedDPoP {
  as: lib.AuthorizationServer
  request: Request
  proofJwk: jose.JWK
  accessToken: string
  proof: string
  jti: string
  jwks: string
}

async function prepareDPoP(proofOverrides: Record<string, unknown> = {}): Promise<PreparedDPoP> {
  const asKey = await lib.generateKeyPair('ES256', { extractable: true })
  const proofKey = await lib.generateKeyPair('ES256')
  const proofJwk = await jose.exportJWK(proofKey.publicKey)
  const now = Math.floor(Date.now() / 1000)
  const as: lib.AuthorizationServer = {
    issuer: 'https://as.example.com',
    jwks_uri: 'https://as.example.com/jwks',
  }

  const accessToken = await new jose.SignJWT({
    iss: as.issuer,
    exp: now + 300,
    aud: 'https://rs.example.com',
    sub: 'sub',
    iat: now,
    jti: 'token-jti',
    client_id: 'client_id',
    cnf: { jkt: await jose.calculateJwkThumbprint(proofJwk) },
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt' })
    .sign(asKey.privateKey)

  const jti = 'proof-jti'
  const proofClaims = {
    iat: now,
    jti,
    htm: 'GET',
    htu: 'https://rs.example.com/resource',
    ath: await accessTokenHash(accessToken),
    ...proofOverrides,
  }
  const proof = await new jose.SignJWT(proofClaims)
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: proofJwk })
    .sign(proofKey.privateKey)

  const publicJwk = await jose.exportJWK(asKey.publicKey)
  const jwks = JSON.stringify({ keys: [publicJwk] })

  const request = new Request('https://rs.example.com/resource?query', {
    headers: {
      authorization: `DPoP ${accessToken}`,
      dpop: proof,
    },
  })

  return { as, request, proofJwk, accessToken, proof, jti, jwks }
}

async function validate(
  prepared: PreparedDPoP,
  dpopReplayStore?: lib.DPoPReplayStore,
  request: Request = prepared.request,
) {
  return lib.validateJwtAccessToken(prepared.as, request, 'https://rs.example.com', {
    [lib.customFetch]: async () =>
      new Response(prepared.jwks, { headers: { 'content-type': 'application/json' } }),
    dpopReplayStore,
  })
}

class MemoryReplayStore implements lib.DPoPReplayStore {
  readonly consumed: string[] = []

  private readonly result: boolean

  constructor(result: boolean = true) {
    this.result = result
  }

  async consume(jti: string): Promise<boolean> {
    this.consumed.push(jti)
    return this.result
  }
}

test('validateJwtAccessToken() DPoP replay store consumes the proof jti on success', async () => {
  const prepared = await prepareDPoP()
  const replayStore = new MemoryReplayStore()

  const claims = await validate(prepared, replayStore)

  assert.strictEqual(claims.sub, 'sub')
  assert.deepStrictEqual(replayStore.consumed, [prepared.jti])
})

test('validateJwtAccessToken() DPoP proof replay is rejected with a distinct error code', async () => {
  const prepared = await prepareDPoP()
  const seen = new Set<string>()
  const replayStore: lib.DPoPReplayStore = {
    async consume(jti: string) {
      if (seen.has(jti)) {
        return false
      }
      seen.add(jti)
      return true
    },
  }

  const claims = await validate(prepared, replayStore)
  assert.strictEqual(claims.sub, 'sub')

  await assert.rejects(validate(prepared, replayStore), (error: unknown) => {
    assert.ok(error instanceof lib.OperationProcessingError)
    assert.strictEqual(error.code, lib.DPOP_PROOF_REPLAY)
    assert.strictEqual(error.message, 'DPoP Proof jti has already been used')
    return true
  })
})

test('validateJwtAccessToken() DPoP replay store failures are distinguishable from replays', async () => {
  const prepared = await prepareDPoP()
  const cause = new Error('the store is down')
  const replayStore: lib.DPoPReplayStore = {
    async consume() {
      throw cause
    },
  }

  await assert.rejects(validate(prepared, replayStore), (error: unknown) => {
    assert.ok(error instanceof lib.OperationProcessingError)
    assert.strictEqual(error.code, lib.DPOP_REPLAY_STORE_ERROR)
    assert.notStrictEqual(error.code, lib.DPOP_PROOF_REPLAY)
    assert.strictEqual((error as lib.OperationProcessingError).cause, cause)
    return true
  })
})

test('validateJwtAccessToken() DPoP validation failures never write to the replay store', async () => {
  const now = Math.floor(Date.now() / 1000)
  const cases: Record<string, Record<string, unknown>> = {
    'htm mismatch': { htm: 'POST' },
    'htu mismatch': { htu: 'https://rs.example.com/somewhere-else' },
    'ath mismatch': { ath: 'not-the-access-token-hash' },
    'stale iat': { iat: now - 301 },
  }

  for (const [name, overrides] of Object.entries(cases)) {
    const prepared = await prepareDPoP(overrides)
    const replayStore = new MemoryReplayStore()

    await assert.rejects(validate(prepared, replayStore), (error: unknown) => {
      assert.ok(error instanceof lib.OperationProcessingError, name)
      assert.notStrictEqual(error.code, lib.DPOP_PROOF_REPLAY)
      assert.notStrictEqual(error.code, lib.DPOP_REPLAY_STORE_ERROR)
      return true
    })
    assert.deepStrictEqual(replayStore.consumed, [], name)
  }
})

test('validateJwtAccessToken() DPoP proof signature failures never write to the replay store', async () => {
  const prepared = await prepareDPoP()
  const replayStore = new MemoryReplayStore()
  const otherKey = await lib.generateKeyPair('ES256')
  const now = Math.floor(Date.now() / 1000)
  const mangledProof = await new jose.SignJWT({
    iat: now,
    jti: prepared.jti,
    htm: 'GET',
    htu: 'https://rs.example.com/resource',
    ath: await accessTokenHash(prepared.accessToken),
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: prepared.proofJwk })
    .sign(otherKey.privateKey)

  const request = new Request('https://rs.example.com/resource', {
    headers: {
      authorization: `DPoP ${prepared.accessToken}`,
      dpop: mangledProof,
    },
  })

  await assert.rejects(validate(prepared, replayStore, request))
  assert.deepStrictEqual(replayStore.consumed, [])
})

test('validateJwtAccessToken() JWT access token signature failures never write to the replay store', async () => {
  const prepared = await prepareDPoP()
  const replayStore = new MemoryReplayStore()
  const request = new Request('https://rs.example.com/resource', {
    headers: {
      authorization: `DPoP ${mangleJwtSignature(prepared.accessToken)}`,
      dpop: prepared.proof,
    },
  })

  await assert.rejects(validate(prepared, replayStore, request))
  assert.deepStrictEqual(replayStore.consumed, [])
})

test('validateJwtAccessToken() DPoP replay consumption is atomic across concurrent requests', async () => {
  const prepared = await prepareDPoP()
  let resolveHeldConsume: (value: boolean) => void = () => {}
  let signalFirstConsumeEntered: () => void = () => {}
  const firstConsumeEntered = new Promise<void>((resolve) => {
    signalFirstConsumeEntered = resolve
  })
  let firstConsumeStarted = false
  const replayStore: lib.DPoPReplayStore = {
    consume(_jti: string): Promise<boolean> {
      if (!firstConsumeStarted) {
        firstConsumeStarted = true
        signalFirstConsumeEntered()
        return new Promise<boolean>((resolve) => {
          resolveHeldConsume = resolve
        })
      }
      return Promise.resolve(false)
    },
  }

  const first = validate(prepared, replayStore)
  await firstConsumeEntered
  const second = validate(prepared, replayStore)

  resolveHeldConsume(true)
  const claims = await first
  assert.strictEqual(claims.sub, 'sub')
  await assert.rejects(second, { code: lib.DPOP_PROOF_REPLAY })
})

test('validateJwtAccessToken() plain Bearer requests never touch the DPoP replay store', async () => {
  const prepared = await prepareDPoP()
  const asKey = await lib.generateKeyPair('ES256', { extractable: true })
  const now = Math.floor(Date.now() / 1000)
  const accessToken = await new jose.SignJWT({
    iss: prepared.as.issuer,
    exp: now + 300,
    aud: 'https://rs.example.com',
    sub: 'sub',
    iat: now,
    jti: 'token-jti',
    client_id: 'client_id',
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'at+jwt' })
    .sign(asKey.privateKey)

  const publicJwk = await jose.exportJWK(asKey.publicKey)
  const jwksResponse = new Response(JSON.stringify({ keys: [publicJwk] }), {
    headers: { 'content-type': 'application/json' },
  })
  const request = new Request('https://rs.example.com/resource', {
    headers: { authorization: `Bearer ${accessToken}` },
  })
  const replayStore = new MemoryReplayStore()

  const claims = await lib.validateJwtAccessToken(prepared.as, request, 'https://rs.example.com', {
    [lib.customFetch]: async () => jwksResponse,
    dpopReplayStore: replayStore,
  })

  assert.strictEqual(claims.sub, 'sub')
  assert.deepStrictEqual(replayStore.consumed, [])
})

test('validateJwtAccessToken() without a DPoP replay store keeps returning claims', async () => {
  const prepared = await prepareDPoP()

  const first = await validate(prepared)
  const second = await validate(prepared)

  assert.strictEqual(first.sub, 'sub')
  assert.strictEqual(second.sub, 'sub')
})

for (const dpopReplayStore of [null, {}, { consume: 'not a function' }, 'no-store']) {
  test(`validateJwtAccessToken() rejects an invalid DPoP replay store (${JSON.stringify(
    dpopReplayStore,
  )})`, async () => {
    const prepared = await prepareDPoP()

    await assert.rejects(
      lib.validateJwtAccessToken(prepared.as, prepared.request, 'https://rs.example.com', {
        [lib.customFetch]: async () =>
          new Response(prepared.jwks, { headers: { 'content-type': 'application/json' } }),
        dpopReplayStore: dpopReplayStore as unknown as lib.DPoPReplayStore,
      }),
      {
        name: 'TypeError',
        code: 'ERR_INVALID_ARG_VALUE',
        message: '"options.dpopReplayStore" must implement a "consume" method',
      },
    )
  })
}
