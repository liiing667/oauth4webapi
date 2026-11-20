import test, { before, after } from 'node:test'
import assert from 'node:assert/strict'
import { captureRejection } from './_errors.js'

import setup, {
  client,
  endpoint,
  issuer,
  setupJwks,
  teardown,
  type ContextWithAlgs,
} from './_setup.js'
import * as lib from './_lib.js'
import { RefreshSessionManager, type RefreshSession } from '../src/refresh-session.js'

const context = {} as ContextWithAlgs

before(() => setup(context))
after(() => teardown(context))
before(() => setupJwks(context))

const tClient: lib.Client = { ...client }

let pathCounter = 0
function tokenPath() {
  pathCounter += 1
  return `/token-rs-${pathCounter}`
}

function issuerFor(pathname: string): lib.AuthorizationServer {
  return { ...issuer, token_endpoint: endpoint(pathname.slice(1)) }
}

type TokenReply =
  | { status?: number; body: Record<string, unknown> }
  | { error: Error }
  | { gate: Promise<void>; status?: number; body: Record<string, unknown> }

interface FakeEndpoint {
  pathname: string
  requests: URLSearchParams[]
  fetch: NonNullable<lib.TokenEndpointRequestOptions[typeof lib.customFetch]>
  queue(reply: TokenReply): void
}

// A customFetch-based token endpoint. It records every request body (so refresh token consumption
// is observable) and serves queued replies, optionally waiting on a gate to hold a request in
// flight for concurrency tests.
function fakeEndpoint(): FakeEndpoint {
  const pathname = tokenPath()
  const replies: TokenReply[] = []
  const requests: URLSearchParams[] = []

  const fetchFn: FakeEndpoint['fetch'] = async (_url, init) => {
    const params = new URLSearchParams(init?.body)
    requests.push(params)

    const reply = replies.shift()
    if (!reply) {
      throw new Error('fake token endpoint: no queued reply')
    }

    if ('gate' in reply) {
      await reply.gate
    }
    if ('error' in reply) {
      throw reply.error
    }

    const status = reply.status ?? 200
    return new Response(JSON.stringify(reply.body), {
      status,
      headers: { 'content-type': 'application/json' },
    })
  }

  return {
    pathname,
    requests,
    fetch: fetchFn,
    queue(reply: TokenReply) {
      replies.push(reply)
    },
  }
}

function gate(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void
  const promise = new Promise<void>((res) => {
    resolve = res
  })
  return { promise, resolve }
}

function managerFor(ep: FakeEndpoint, refreshToken = 'rt-0') {
  return new RefreshSessionManager(issuerFor(ep.pathname), tClient, lib.None(), {
    access_token: 'old-access',
    token_type: 'bearer',
    refresh_token: refreshToken,
  })
}

function refreshOptions(ep: FakeEndpoint): lib.TokenEndpointRequestOptions {
  return { [lib.customFetch]: ep.fetch }
}

interface NaiveSession {
  access_token: string
  refresh_token: string
}

// Models the caller pattern from examples/refresh_token.ts: every call sends the currently stored
// refresh token and overwrites the whole session from the response.
async function naiveRefresh(ep: FakeEndpoint, session: NaiveSession): Promise<NaiveSession> {
  const response = await lib.refreshTokenGrantRequest(
    issuerFor(ep.pathname),
    tClient,
    lib.None(),
    session.refresh_token,
    { [lib.customFetch]: ep.fetch },
  )
  const result = await lib.processRefreshTokenResponse(issuerFor(ep.pathname), tClient, response)
  return {
    access_token: result.access_token,
    refresh_token: result.refresh_token ?? session.refresh_token,
  }
}

test('reproduction: concurrent naive refreshes consume the same refresh token twice', async () => {
  const ep = fakeEndpoint()
  const held = gate()
  ep.queue({
    gate: held.promise,
    body: { access_token: 'a1', token_type: 'Bearer', refresh_token: 'rotated' },
  })
  ep.queue({
    gate: held.promise,
    body: { access_token: 'a2', token_type: 'Bearer', refresh_token: 'rotated' },
  })

  const session: NaiveSession = { access_token: 'old-access', refresh_token: 'rt-0' }
  const results = Promise.allSettled([naiveRefresh(ep, session), naiveRefresh(ep, session)])
  held.resolve()
  await results

  assert.deepEqual(
    ep.requests.map((params) => params.get('refresh_token')),
    ['rt-0', 'rt-0'],
  )
})

test('reproduction: an auto-retry after a failure keeps consuming the old refresh token', async () => {
  const ep = fakeEndpoint()
  ep.queue({ status: 400, body: { error: 'invalid_grant' } })
  ep.queue({ body: { access_token: 'new-access', token_type: 'Bearer', refresh_token: 'rotated' } })

  const session: NaiveSession = { access_token: 'old-access', refresh_token: 'rt-0' }

  const error = await captureRejection(() => naiveRefresh(ep, session))
  assert.equal((error as lib.ResponseBodyError).error, 'invalid_grant')

  const retried = await naiveRefresh(ep, session)
  assert.deepEqual(retried, { access_token: 'new-access', refresh_token: 'rotated' })

  assert.deepEqual(
    ep.requests.map((params) => params.get('refresh_token')),
    ['rt-0', 'rt-0'],
  )
})

test('one generation submits a single request for concurrent refreshes', async () => {
  const ep = fakeEndpoint()
  const held = gate()
  ep.queue({
    gate: held.promise,
    body: { access_token: 'new-access', token_type: 'Bearer', refresh_token: 'rt-1' },
  })

  const manager = managerFor(ep)
  const pending = Promise.all([
    manager.refresh({ requestOptions: refreshOptions(ep) }),
    manager.refresh({ requestOptions: refreshOptions(ep) }),
    manager.refresh({ requestOptions: refreshOptions(ep) }),
  ])

  held.resolve()
  const [first, second, third] = await pending

  assert.deepEqual(
    ep.requests.map((params) => params.get('refresh_token')),
    ['rt-0'],
  )
  for (const result of [first, second, third]) {
    assert.equal(result.access_token, 'new-access')
    assert.equal(result.refresh_token, 'rt-1')
    assert.equal(result.generation, 1)
  }
  assert.equal(manager.getSession().generation, 1)
  assert.throws(() => {
    ;(first as { access_token: string }).access_token = 'tampered'
  })
})

test('a failed attempt leaves the previous session and generation untouched', async () => {
  const ep = fakeEndpoint()
  ep.queue({ status: 400, body: { error: 'temporarily_unavailable' } })

  const manager = managerFor(ep)
  const before = manager.getSession()

  const error = await captureRejection(() =>
    manager.refresh({ requestOptions: refreshOptions(ep) }),
  )
  assert.equal((error as lib.ResponseBodyError).error, 'temporarily_unavailable')

  const after = manager.getSession()
  assert.deepEqual(after, before)
  assert.equal(after.generation, 0)
  assert.equal(after.refresh_token, 'rt-0')
  assert.equal(manager.hasRefreshToken(), true)
})

test('a network failure does not commit state and a retry reuses the same generation', async () => {
  const ep = fakeEndpoint()
  ep.queue({ error: new TypeError('fetch failed') })
  ep.queue({ body: { access_token: 'new-access', token_type: 'Bearer', refresh_token: 'rt-1' } })

  const manager = managerFor(ep)

  await assert.rejects(
    () => manager.refresh({ requestOptions: refreshOptions(ep) }),
    /fetch failed/,
  )
  assert.equal(manager.getSession().refresh_token, 'rt-0')
  assert.equal(manager.getSession().generation, 0)

  const committed = await manager.refresh({ requestOptions: refreshOptions(ep) })
  assert.equal(committed.generation, 1)
  assert.equal(committed.refresh_token, 'rt-1')
  assert.deepEqual(manager.getSession(), committed)
})

test('an invalid success response is rejected before any commit', async () => {
  const ep = fakeEndpoint()
  ep.queue({ body: { token_type: 'Bearer' } })

  const manager = managerFor(ep)
  const before = manager.getSession()

  await assert.rejects(() => manager.refresh({ requestOptions: refreshOptions(ep) }))
  assert.deepEqual(manager.getSession(), before)
})

test('a successful commit rotates to a new generation and a second refresh uses the new token', async () => {
  const ep = fakeEndpoint()
  ep.queue({ body: { access_token: 'access-1', token_type: 'Bearer', refresh_token: 'rt-1' } })
  ep.queue({ body: { access_token: 'access-2', token_type: 'Bearer', refresh_token: 'rt-2' } })

  const manager = managerFor(ep)

  const first = await manager.refresh({ requestOptions: refreshOptions(ep) })
  assert.equal(first.generation, 1)
  assert.equal(first.refresh_token, 'rt-1')

  const second = await manager.refresh({ requestOptions: refreshOptions(ep) })
  assert.equal(second.generation, 2)
  assert.equal(second.access_token, 'access-2')
  assert.equal(second.refresh_token, 'rt-2')

  assert.deepEqual(
    ep.requests.map((params) => params.get('refresh_token')),
    ['rt-0', 'rt-1'],
  )
})

test('a response without a refresh token keeps the same refresh token in a new generation', async () => {
  const ep = fakeEndpoint()
  ep.queue({ body: { access_token: 'access-1', token_type: 'Bearer', expires_in: 60 } })

  const manager = managerFor(ep, 'reusable-rt')
  const committed = await manager.refresh({ requestOptions: refreshOptions(ep) })

  assert.equal(committed.refresh_token, 'reusable-rt')
  assert.equal(committed.expires_in, 60)
  assert.equal(committed.generation, 1)
  assert.equal(manager.getSession().refresh_token, 'reusable-rt')
})

test('scope down-scoping is sent as a request parameter without mutating the stored session', async () => {
  const ep = fakeEndpoint()
  ep.queue({
    body: {
      access_token: 'scoped-access',
      token_type: 'Bearer',
      refresh_token: 'rt-1',
      scope: 'api:read',
    },
  })

  const manager = managerFor(ep)
  const committed = await manager.refresh({
    scope: 'api:read',
    requestOptions: refreshOptions(ep),
  })

  assert.equal(committed.scope, 'api:read')
  assert.equal(committed.generation, 1)
  assert.equal(ep.requests[0].get('grant_type'), 'refresh_token')
  assert.equal(ep.requests[0].get('refresh_token'), 'rt-0')
  assert.equal(ep.requests[0].get('scope'), 'api:read')
})

test('events expose the ordering of concurrent, failed and successful attempts', async () => {
  const ep = fakeEndpoint()
  ep.queue({ status: 500, body: { error: 'server_error' } })
  const held = gate()
  ep.queue({
    gate: held.promise,
    body: { access_token: 'new-access', token_type: 'Bearer', refresh_token: 'rt-1' },
  })

  const manager = managerFor(ep)
  const events: string[] = []
  manager.addListener((event) => {
    events.push(
      `${event.kind}:g${event.generation}:a${event.attempt}${
        event.session ? `->g${event.session.generation}` : ''
      }`,
    )
  })

  await assert.rejects(() => manager.refresh({ requestOptions: refreshOptions(ep) }))

  const pending = Promise.all([
    manager.refresh({ requestOptions: refreshOptions(ep) }),
    manager.refresh({ requestOptions: refreshOptions(ep) }),
  ])
  held.resolve()
  await pending

  assert.deepEqual(events, [
    'refresh-started:g0:a1',
    'refresh-failed:g0:a1',
    'refresh-started:g0:a2',
    'refresh-succeeded:g0:a2->g1',
  ])
})

test('all concurrent waiters observe the same failure without a second request', async () => {
  const ep = fakeEndpoint()
  const held = gate()
  ep.queue({ gate: held.promise, status: 400, body: { error: 'invalid_grant' } })

  const manager = managerFor(ep)
  const pending = Promise.allSettled([
    manager.refresh({ requestOptions: refreshOptions(ep) }),
    manager.refresh({ requestOptions: refreshOptions(ep) }),
  ])
  held.resolve()
  const results = await pending

  assert.equal(results[0].status, 'rejected')
  assert.equal(results[1].status, 'rejected')
  assert.equal(ep.requests.length, 1)
  assert.equal(manager.getSession().generation, 0)
})

test('refresh() rejects when the session has no refresh token', async () => {
  const ep = fakeEndpoint()
  const manager = new RefreshSessionManager(issuerFor(ep.pathname), tClient, lib.None(), {
    access_token: 'access',
    token_type: 'bearer',
  })

  assert.equal(manager.hasRefreshToken(), false)
  await assert.rejects(() => manager.refresh(), /no "refresh_token"/)
  const snapshot: RefreshSession = manager.getSession()
  assert.equal(snapshot.generation, 0)
  assert.equal(ep.requests.length, 0)
})
