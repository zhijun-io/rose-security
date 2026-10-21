import assert from 'node:assert/strict'
import test from 'node:test'
import { getHealth } from './healthClient.js'

test('reads the backend health response', async () => {
  const result = await getHealth(async (url, options) => {
    assert.equal(url, '/api/sample/health')
    assert.equal(options.headers.Accept, 'application/json, application/problem+json')
    return Response.json({ status: 'ok' })
  })

  assert.deepEqual(result, { status: 'ok' })
})

test('uses a Problem Detail message for failed API responses', async () => {
  await assert.rejects(
    getHealth(async () => Response.json({ detail: 'Backend unavailable' }, { status: 503 })),
    { message: 'Backend unavailable' },
  )
})

test('reports network failures without exposing implementation details', async () => {
  await assert.rejects(getHealth(async () => { throw new TypeError('socket internals') }), {
    message: '无法连接后端 API',
  })
})
