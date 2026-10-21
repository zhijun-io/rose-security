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
