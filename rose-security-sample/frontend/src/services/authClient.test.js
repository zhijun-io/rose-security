import assert from 'node:assert/strict'
import test from 'node:test'
import { getProfile, login, logout, refresh } from './authClient.js'

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
