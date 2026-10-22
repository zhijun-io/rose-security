async function requestJson(path, options, fetchImpl) {
  let response
  try {
    response = await fetchImpl(path, options)
  } catch {
    throw new Error('无法连接后端 API')
  }

  if (response.status === 204) return null
  const body = await response.json().catch(() => null)
  if (!response.ok) {
    const error = new Error(body?.detail || body?.title || `HTTP ${response.status}`)
    error.status = response.status
    throw error
  }
  return body
}

function post(path, body, fetchImpl, accessToken) {
  return requestJson(path, {
    method: 'POST',
    headers: {
      Accept: 'application/json, application/problem+json',
      'Content-Type': 'application/json',
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
    },
    body: JSON.stringify(body),
  }, fetchImpl)
}

export function login(email, password, fetchImpl = fetch) {
  return post('/api/auth/login', { email, password }, fetchImpl)
}

export function verifyMfaLogin(transactionToken, method, proof, fetchImpl = fetch) {
  return post('/api/auth/mfa/verify', { transaction_token: transactionToken, method, proof }, fetchImpl)
}

export function beginWebAuthnLogin(transactionToken, fetchImpl = fetch) {
  return post('/api/auth/mfa/webauthn/options', { transaction_token: transactionToken }, fetchImpl)
}

export function beginWebAuthnRegistration(accessToken, fetchImpl = fetch) {
  return post('/api/me/mfa/webauthn/register/options', {}, fetchImpl, accessToken)
}

export function completeWebAuthnRegistration(accessToken, challengeToken, credential, label, fetchImpl = fetch) {
  return post('/api/me/mfa/webauthn/register', {
    challenge_token: challengeToken,
    publicKey: { credential, label },
  }, fetchImpl, accessToken)
}

export function beginWebAuthnRemoval(accessToken, credentialId, fetchImpl = fetch) {
  return post('/api/me/mfa/webauthn/remove/options', { credential_id: credentialId }, fetchImpl, accessToken)
}

export function completeWebAuthnRemoval(accessToken, challengeToken, credentialId, credential, fetchImpl = fetch) {
  return post('/api/me/mfa/webauthn/remove', {
    challenge_token: challengeToken,
    credential_id: credentialId,
    proof: credential,
  }, fetchImpl, accessToken)
}

export function refresh(refreshToken, fetchImpl = fetch) {
  return post('/api/auth/refresh', { refresh_token: refreshToken }, fetchImpl)
}

export function logout(accessToken, fetchImpl = fetch) {
  return post('/api/auth/logout', {}, fetchImpl, accessToken)
}

export function logoutAll(accessToken, fetchImpl = fetch) {
  return post('/api/auth/logout-all', {}, fetchImpl, accessToken)
}

export function getProfile(accessToken, fetchImpl = fetch) {
  return requestJson('/api/sample/profile', {
    headers: {
      Accept: 'application/json, application/problem+json',
      Authorization: `Bearer ${accessToken}`,
    },
  }, fetchImpl)
}

export function getSessions(accessToken, fetchImpl = fetch) {
  return requestJson('/api/sample/sessions', {
    headers: {
      Accept: 'application/json, application/problem+json',
      Authorization: `Bearer ${accessToken}`,
    },
  }, fetchImpl)
}

export function getTotpStatus(accessToken, fetchImpl = fetch) {
  return requestJson('/api/me/mfa', {
    headers: { Accept: 'application/json, application/problem+json', Authorization: `Bearer ${accessToken}` },
  }, fetchImpl)
}

export function beginTotpEnrollment(accessToken, fetchImpl = fetch) {
  return post('/api/me/mfa/totp', {}, fetchImpl, accessToken)
}

export function confirmTotpEnrollment(accessToken, code, fetchImpl = fetch) {
  return post('/api/me/mfa/totp/verify', { code }, fetchImpl, accessToken)
}

export function removeTotp(accessToken, code, fetchImpl = fetch) {
  return requestJson('/api/me/mfa/totp', {
    method: 'DELETE',
    headers: {
      Accept: 'application/json, application/problem+json',
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify({ code }),
  }, fetchImpl)
}

export function beginEmailEnrollment(accessToken, fetchImpl = fetch) {
  return post('/api/me/mfa/email', {}, fetchImpl, accessToken)
}

export function confirmEmailEnrollment(accessToken, challengeToken, code, fetchImpl = fetch) {
  return post('/api/me/mfa/email/verify', { challenge_token: challengeToken, code }, fetchImpl, accessToken)
}

export function beginEmailRemoval(accessToken, fetchImpl = fetch) {
  return requestJson('/api/me/mfa/email', {
    method: 'DELETE',
    headers: { Accept: 'application/json, application/problem+json', Authorization: `Bearer ${accessToken}` },
  }, fetchImpl)
}

export function confirmEmailRemoval(accessToken, challengeToken, code, fetchImpl = fetch) {
  return post('/api/me/mfa/email/remove/verify', { challenge_token: challengeToken, code }, fetchImpl, accessToken)
}
