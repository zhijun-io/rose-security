import assert from 'node:assert/strict'
import test from 'node:test'
import { beginEmailEnrollment, beginEmailRemoval, beginTotpEnrollment, beginWebAuthnLogin, beginWebAuthnRegistration, beginWebAuthnRemoval, completeWebAuthnRegistration, completeWebAuthnRemoval, confirmEmailEnrollment, confirmEmailRemoval, confirmTotpEnrollment, getProfile, getTotpStatus, login, logout, refresh, removeTotp, verifyMfaLogin } from './authClient.js'

test('login sends an email and password to the filter endpoint', async () => {
  let request
  await login('demo@example.test', 'secret', async (url, options) => {
    request = { url, options }
    return Response.json({ access_token: 'access' })
  })

  assert.equal(request.url, '/api/auth/login')
  assert.deepEqual(JSON.parse(request.options.body), { email: 'demo@example.test', password: 'secret' })
})

test('refresh submits the opaque refresh token in the response-body contract', async () => {
  let request
  await refresh('opaque-refresh-value', async (url, options) => {
    request = { url, options }
    return Response.json({ access_token: 'new-access' })
  })

  assert.equal(request.url, '/api/auth/refresh')
  assert.deepEqual(JSON.parse(request.options.body), { refresh_token: 'opaque-refresh-value' })
})

test('profile uses the bearer access token and logout revokes the bearer session', async () => {
  const requests = []
  const fetchImpl = async (url, options) => {
    requests.push({ url, options })
    return url.endsWith('/logout') ? new Response(null, { status: 204 }) : Response.json({ email: 'demo@example.test' })
  }

  await getProfile('access-value', fetchImpl)
  await logout('access-value', fetchImpl)

  assert.equal(requests[0].options.headers.Authorization, 'Bearer access-value')
  assert.equal(requests[1].url, '/api/auth/logout')
  assert.equal(requests[1].options.headers.Authorization, 'Bearer access-value')
})

test('authentication client surfaces a generic ProblemDetail message', async () => {
  await assert.rejects(
    login('demo@example.test', 'wrong', async () => Response.json(
      { detail: 'Authentication failed' },
      { status: 401, headers: { 'Content-Type': 'application/problem+json' } },
    )),
    /Authentication failed/,
  )
})

test('TOTP and email MFA enrollment and removal use factor verification endpoints', async () => {
  const requests = []
  const fetchImpl = async (url, options) => {
    requests.push({ url, options })
    return url.endsWith('/mfa')
      ? Response.json({ totpEnrolled: false })
      : Response.json({ status: 'mfa_required', transaction_token: 'pending' })
  }

  await getTotpStatus('access', fetchImpl)
  await beginTotpEnrollment('access', fetchImpl)
  await confirmTotpEnrollment('access', '123456', fetchImpl)
  await removeTotp('access', '123456', fetchImpl)
  await beginEmailEnrollment('access', fetchImpl)
  await confirmEmailEnrollment('access', 'enrollment-token', '123456', fetchImpl)
  await beginEmailRemoval('access', fetchImpl)
  await confirmEmailRemoval('access', 'removal-token', '123456', fetchImpl)
  await verifyMfaLogin('pending', 'totp', '112233', fetchImpl)

  assert.deepEqual(requests.map(({ url }) => url), [
    '/api/me/mfa',
    '/api/me/mfa/totp',
    '/api/me/mfa/totp/verify',
    '/api/me/mfa/totp',
    '/api/me/mfa/email',
    '/api/me/mfa/email/verify',
    '/api/me/mfa/email',
    '/api/me/mfa/email/remove/verify',
    '/api/auth/mfa/verify',
  ])
  assert.equal(requests[0].options.headers.Authorization, 'Bearer access')
  assert.equal(requests[3].options.method, 'DELETE')
  assert.equal(requests[3].options.headers.Authorization, 'Bearer access')
  assert.deepEqual(JSON.parse(requests[1].options.body), {})
  assert.deepEqual(JSON.parse(requests[3].options.body), { code: '123456' })
  assert.deepEqual(JSON.parse(requests[5].options.body), { challenge_token: 'enrollment-token', code: '123456' })
  assert.equal(requests[6].options.method, 'DELETE')
  assert.equal(requests[6].options.body, undefined)
  assert.deepEqual(JSON.parse(requests[7].options.body), { challenge_token: 'removal-token', code: '123456' })
  assert.deepEqual(JSON.parse(requests[8].options.body), {
    transaction_token: 'pending',
    method: 'totp',
    proof: '112233',
  })
})

test('WebAuthn MFA uses pending login and authenticated enrollment/removal endpoints', async () => {
  const requests = []
  const fetchImpl = async (url, options) => {
    requests.push({ url, options })
    return new Response(null, { status: 204 })
  }
  const credential = { id: 'credential-id', rawId: 'credential-id' }

  await beginWebAuthnLogin('pending-transaction', fetchImpl)
  await beginWebAuthnRegistration('access-token', fetchImpl)
  await completeWebAuthnRegistration('access-token', 'registration-challenge', credential, 'Laptop', fetchImpl)
  await beginWebAuthnRemoval('access-token', 'credential-id', fetchImpl)
  await completeWebAuthnRemoval('access-token', 'removal-challenge', 'credential-id', credential, fetchImpl)

  assert.deepEqual(requests.map(({ url }) => url), [
    '/api/auth/mfa/webauthn/options',
    '/api/me/mfa/webauthn/register/options',
    '/api/me/mfa/webauthn/register',
    '/api/me/mfa/webauthn/remove/options',
    '/api/me/mfa/webauthn/remove',
  ])
  assert.deepEqual(JSON.parse(requests[0].options.body), { transaction_token: 'pending-transaction' })
  assert.equal(requests[0].options.headers.Authorization, undefined)
  assert.equal(requests[1].options.headers.Authorization, 'Bearer access-token')
  assert.deepEqual(JSON.parse(requests[2].options.body), {
    challenge_token: 'registration-challenge',
    publicKey: { credential, label: 'Laptop' },
  })
  assert.deepEqual(JSON.parse(requests[4].options.body), {
    challenge_token: 'removal-challenge',
    credential_id: 'credential-id',
    proof: credential,
  })
})
