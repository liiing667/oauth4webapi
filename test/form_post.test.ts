import test, { before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import * as jose from 'jose'
import setup, { client, endpoint, setupJwks, teardown, type ContextWithAlgs } from './_setup.js'
import * as lib from './_lib.js'

const context = {} as ContextWithAlgs

before(() => setup(context))
before(() => setupJwks(context))
after(() => teardown(context))

const as: lib.AuthorizationServer = {
  issuer: 'https://op.example.com',
  jwks_uri: endpoint('jwks'),
}
const jwtClient: lib.Client = { ...client, id_token_signed_response_alg: 'ES256' }
const codeHash = createHash('sha256').update('code').digest().subarray(0, 16).toString('base64url')

async function idToken() {
  const now = Math.floor(Date.now() / 1000)
  return new jose.SignJWT({
    iss: as.issuer,
    aud: client.client_id,
    sub: 'subject',
    iat: now,
    exp: now + 300,
    nonce: 'nonce',
    c_hash: codeHash,
  })
    .setProtectedHeader({ alg: 'ES256' })
    .sign(context.ES256.privateKey)
}

function formPostBody(parameters: Record<string, string>) {
  return new URLSearchParams(parameters).toString()
}

function formPostRequest(body: BodyInit | null) {
  const init: RequestInit & { duplex?: 'half' } = {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
    duplex: body instanceof ReadableStream ? 'half' : undefined,
  }
  return new Request('https://rp.example.com/callback', init)
}

/**
 * Instruments a ReadableStream's reader so the test can observe exactly how many times the body
 * handed to the Request is read and whether it was cancelled after a failure. The Request body is
 * what the library is allowed to touch, so counting on the underlying source pull/cancel hooks
 * would not be portable across runtimes.
 */
function observedStream(source: UnderlyingDefaultSource<Uint8Array>) {
  const observed = { reads: 0, cancels: 0, getReaders: 0 }
  const stream = new ReadableStream<Uint8Array>(source)
  const getReader = stream.getReader.bind(stream)
  stream.getReader = (() => {
    observed.getReaders += 1
    const reader = getReader() as ReadableStreamDefaultReader<Uint8Array>
    const read = reader.read.bind(reader)
    reader.read = async () => {
      observed.reads += 1
      return read()
    }
    const cancel = reader.cancel.bind(reader)
    reader.cancel = async (reason?: unknown) => {
      observed.cancels += 1
      return cancel(reason)
    }
    return reader
  }) as typeof stream.getReader
  return { stream, observed }
}

for (const [name, validate] of [
  ['validateCodeIdTokenResponse', lib.validateCodeIdTokenResponse],
  ['validateDetachedSignatureResponse', lib.validateDetachedSignatureResponse],
] as const) {
  test(`${name} accepts a valid form_post Request and consumes the body once`, async () => {
    const token = await idToken()
    const body = formPostBody({ code: 'code', id_token: token })
    const request = formPostRequest(body)

    const result = await validate(as, jwtClient, request, 'nonce')
    assert.equal(result.get('code'), 'code')
    assert.equal(request.bodyUsed, true)
  })

  test(`${name} still accepts query/fragment (URL) inputs`, async () => {
    const token = await idToken()
    const url = new URL('https://rp.example.com/callback')
    url.hash = new URLSearchParams({ code: 'code', id_token: token }).toString()

    const result = await validate(as, jwtClient, url, 'nonce')
    assert.equal(result.get('code'), 'code')
  })

  test(`${name} rejects an oversized body after a single bounded read`, async () => {
    const oversized = new Uint8Array(65537).fill(0x61)
    const { stream, observed } = observedStream({
      pull(controller) {
        controller.enqueue(oversized)
        controller.close()
      },
    })
    const request = formPostRequest(stream)

    await assert.rejects(validate(as, jwtClient, request, 'nonce'), {
      code: lib.INVALID_RESPONSE,
      message: /maximum allowed size/,
    })

    assert.equal(observed.reads, 1)
    assert.equal(observed.cancels, 1)
    assert.equal(observed.getReaders, 1)
    assert.equal(request.bodyUsed, true)
  })

  test(`${name} rejects duplicate parameters without re-reading the stream`, async () => {
    const token = await idToken()
    const body = `code=code&code=other&id_token=${encodeURIComponent(token)}`
    const { stream, observed } = observedStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(body))
        controller.close()
      },
    })
    const request = formPostRequest(stream)

    await assert.rejects(validate(as, jwtClient, request, 'nonce'), {
      code: lib.INVALID_RESPONSE,
      message: /"code" parameter must be provided only once/,
    })

    assert.equal(observed.getReaders, 1)
    assert.equal(observed.cancels, 0)
    assert.equal(request.bodyUsed, true)
  })

  test(`${name} rejects a truncated/errored stream after a single read`, async () => {
    const error = new Error('truncated')
    const { stream, observed } = observedStream({
      pull(controller) {
        controller.error(error)
      },
    })
    const request = formPostRequest(stream)

    await assert.rejects(validate(as, jwtClient, request, 'nonce'), error)

    assert.equal(observed.reads, 1)
    assert.equal(observed.cancels, 1)
    assert.equal(observed.getReaders, 1)
    assert.equal(request.bodyUsed, true)
  })

  test(`${name} does not retry a failed stream on a second validation attempt`, async () => {
    const error = new Error('truncated')
    const { stream } = observedStream({
      pull(controller) {
        controller.error(error)
      },
    })
    const request = formPostRequest(stream)

    await assert.rejects(validate(as, jwtClient, request, 'nonce'), error)
    await assert.rejects(validate(as, jwtClient, request, 'nonce'), (error: unknown) => {
      assert.ok(error instanceof TypeError)
      assert.equal((error as Error & { code?: string }).code, 'ERR_INVALID_ARG_VALUE')
      assert.equal(
        (error as Error).message,
        'form_post Request instances must contain a readable body',
      )
      return true
    })
  })
}
