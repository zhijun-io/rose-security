export async function getHealth(fetchImpl = fetch) {
  let response
  try {
    response = await fetchImpl('/api/sample/health', {
      headers: { Accept: 'application/json, application/problem+json' },
    })
  } catch {
    throw new Error('无法连接后端 API')
  }

  if (!response.ok) {
    const problem = await response.json().catch(() => null)
    throw new Error(problem?.detail || problem?.title || `HTTP ${response.status}`)
  }

  return response.json()
}
