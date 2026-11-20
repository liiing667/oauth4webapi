import {
  processRefreshTokenResponse,
  refreshTokenGrantRequest,
  type AuthorizationServer,
  type Client,
  type ClientAuth,
  type ProcessTokenResponseOptions,
  type TokenEndpointResponse,
  type TokenEndpointRequestOptions,
} from './index.js'

/**
 * A snapshot of the caller-side token session managed by {@link RefreshSessionManager}.
 *
 * The `generation` starts at `0` for the initial session and is incremented exactly once for every
 * successfully committed Refresh Token Grant. It never changes for a failed refresh attempt.
 */
export interface RefreshSession {
  access_token: string
  token_type: TokenEndpointResponse['token_type']
  refresh_token?: string
  scope?: string
  expires_in?: number
  /**
   * Monotonic version of the session. `0` is the initial session, each committed refresh increments
   * it by one.
   */
  generation: number
}

/**
 * Options for a single {@link RefreshSessionManager.refresh} attempt.
 *
 * `scope` is forwarded to the Refresh Token Grant as the `scope` request parameter (RFC 6749
 * Section 6, including scope down-scoping per RFC 6749 Section 3.3). It does not mutate the stored
 * session; the authorization server's response decides the resulting session scope.
 */
export interface RefreshAttemptOptions {
  scope?: string
  requestOptions?: TokenEndpointRequestOptions
  processOptions?: ProcessTokenResponseOptions
}

/**
 * Kind of a {@link RefreshSessionEvent}.
 *
 * - `refresh-started`: a new generation attempt began, exactly one Refresh Token Grant request is in
 *   flight.
 * - `refresh-succeeded`: the response was validated and committed, the session moved to a new
 *   generation.
 * - `refresh-failed`: the request or response processing failed; the previous session is untouched.
 */
export type RefreshSessionEventKind = 'refresh-started' | 'refresh-succeeded' | 'refresh-failed'

export interface RefreshSessionEvent {
  kind: RefreshSessionEventKind
  /**
   * Generation that the event belongs to; it equals the current session generation on start.
   */
  generation: number
  /**
   * Monotonic counter of refresh attempts, including failed and deduplicated ones.
   */
  attempt: number
  /**
   * Present only for `refresh-failed` events.
   */
  error?: unknown
  /**
   * Present only for `refresh-succeeded` events.
   */
  session?: RefreshSession
}

export type RefreshSessionListener = (event: RefreshSessionEvent) => void

/**
 * Caller-side state machine for Refresh Token Grants with refresh token rotation.
 *
 * It provides three guarantees that plain request/response calls cannot:
 *
 * 1. One generation submits at most one Refresh Token Grant request. Concurrent `refresh()` calls
 *    while a refresh is in flight join the same attempt (single-flight) instead of consuming the
 *    same refresh token twice.
 * 2. A failed attempt (network error, OAuth error response, invalid response body) never mutates the
 *    stored session; the still-valid refresh token can be retried afterwards as a new attempt of
 *    the same generation.
 * 3. The session moves to a new generation only after the response is fully validated, and the rotated
 *    refresh token is committed atomically together with the rest of the token response.
 *
 * The manager is intentionally transport-agnostic: it only composes the library's
 * {@link refreshTokenGrantRequest} and {@link processRefreshTokenResponse} functions.
 */
export class RefreshSessionManager {
  private readonly as: AuthorizationServer
  private readonly client: Client
  private readonly clientAuth: ClientAuth
  private session: RefreshSession
  private inflight: Promise<RefreshSession> | undefined
  private generation = 0
  private attempt = 0
  private readonly listeners = new Set<RefreshSessionListener>()

  constructor(
    as: AuthorizationServer,
    client: Client,
    clientAuth: ClientAuth,
    initial: Pick<RefreshSession, 'access_token' | 'token_type'> &
      Partial<Omit<RefreshSession, 'access_token' | 'token_type' | 'generation'>>,
  ) {
    this.as = as
    this.client = client
    this.clientAuth = clientAuth
    this.session = { ...initial, generation: this.generation }
  }

  addListener(listener: RefreshSessionListener): () => void {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  private emit(event: RefreshSessionEvent) {
    for (const listener of this.listeners) {
      listener(event)
    }
  }

  /**
   * Returns a frozen snapshot of the current session.
   */
  getSession(): RefreshSession {
    return Object.freeze({ ...this.session })
  }

  /**
   * Whether the current session holds a refresh token usable for another attempt.
   */
  hasRefreshToken(): boolean {
    return typeof this.session.refresh_token === 'string'
  }

  /**
   * Performs a Refresh Token Grant for the current generation.
   *
   * Concurrent calls share one in-flight attempt. On success the session is committed as a new
   * generation and the same resolved snapshot is returned to every waiter. On failure the session
   * is left untouched and the rejection is propagated to every waiter; a later call starts a fresh
   * attempt of the same generation.
   */
  async refresh(options?: RefreshAttemptOptions): Promise<RefreshSession> {
    if (this.inflight) {
      return this.inflight
    }

    const refreshToken = this.session.refresh_token
    if (typeof refreshToken !== 'string') {
      throw new TypeError('the current session has no "refresh_token" to refresh with')
    }

    const generation = this.generation
    const attempt = ++this.attempt
    const parameters = new URLSearchParams(options?.requestOptions?.additionalParameters)
    if (options?.scope !== undefined) {
      parameters.set('scope', options.scope)
    }

    this.emit({ kind: 'refresh-started', generation, attempt })

    const promise = (async () => {
      try {
        const response = await refreshTokenGrantRequest(
          this.as,
          this.client,
          this.clientAuth,
          refreshToken,
          { ...options?.requestOptions, additionalParameters: parameters },
        )

        const result = await processRefreshTokenResponse(
          this.as,
          this.client,
          response,
          options?.processOptions,
        )

        const next: RefreshSession = {
          access_token: result.access_token,
          token_type: result.token_type,
          refresh_token: result.refresh_token === undefined ? refreshToken : result.refresh_token,
          scope: result.scope,
          expires_in: result.expires_in,
          generation: generation + 1,
        }

        this.session = next
        this.generation += 1
        const snapshot = this.getSession()
        this.emit({ kind: 'refresh-succeeded', generation, attempt, session: snapshot })
        return snapshot
      } catch (error) {
        this.emit({ kind: 'refresh-failed', generation, attempt, error })
        throw error
      } finally {
        this.inflight = undefined
      }
    })()

    this.inflight = promise
    return promise
  }
}
