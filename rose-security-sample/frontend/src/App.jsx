import { useCallback, useEffect, useState } from 'react'
import { getHealth } from './services/healthClient.js'
import { getProfile, getSessions, login, logout, logoutAll, refresh } from './services/authClient.js'
import LoginPage from './LoginPage.jsx'

const SESSION_STORAGE_KEY = 'rose-security-session'

function readStoredSession() {
  if (typeof window === 'undefined') return null
  let session
  try {
    session = JSON.parse(window.sessionStorage.getItem(SESSION_STORAGE_KEY))
  } catch {
    clearStoredSession()
    return null
  }
  if (session?.tokens?.access_token && session?.tokens?.refresh_token && session?.profile?.email) return session
  clearStoredSession()
  return null
}

function storeSession(tokens, profile) {
  try {
    window.sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify({ tokens, profile }))
  } catch {
    // Keep the active session usable if browser storage is unavailable.
  }
}

function clearStoredSession() {
  try {
    window.sessionStorage.removeItem(SESSION_STORAGE_KEY)
  } catch {
    // There is no persisted session to clear when browser storage is unavailable.
  }
}

function orderSessions(sessions) {
  return [...sessions].sort((left, right) => Number(right.current) - Number(left.current))
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString('zh-CN') : '—'
}

function formatAuthenticationMethods(methods) {
  return methods?.map((method) => method === 'pwd' ? '邮箱与密码' : method).join(' · ') || '邮箱与密码'
}

let pendingSessionRestore

function restoreStoredSession(session) {
  if (pendingSessionRestore?.refreshToken === session.tokens.refresh_token) return pendingSessionRestore.promise

  const promise = (async () => {
    let tokens = session.tokens
    let profile = session.profile
    try {
      try {
        profile = await getProfile(tokens.access_token)
      } catch (error) {
        if (error.status !== 401) throw error
        tokens = await refresh(tokens.refresh_token)
        profile = await getProfile(tokens.access_token)
      }
      return { tokens, profile }
    } catch (error) {
      return { tokens, profile, error }
    }
  })().finally(() => {
    if (pendingSessionRestore?.promise === promise) pendingSessionRestore = undefined
  })

  pendingSessionRestore = { refreshToken: session.tokens.refresh_token, promise }
  return promise
}

export default function App() {
  const [storedSession] = useState(readStoredSession)
  const [apiState, setApiState] = useState('checking')
  const [email, setEmail] = useState('demo@example.test')
  const [password, setPassword] = useState('')
  const [tokens, setTokens] = useState(() => storedSession?.tokens ?? null)
  const [profile, setProfile] = useState(() => storedSession?.profile ?? null)
  const [sessions, setSessions] = useState([])
  const [sessionsLoading, setSessionsLoading] = useState(false)
  const [sessionsError, setSessionsError] = useState('')
  const [sessionReady, setSessionReady] = useState(() => !storedSession)
  const [authBusy, setAuthBusy] = useState(false)
  const [authMessage, setAuthMessage] = useState('')
  const [authMessageTone, setAuthMessageTone] = useState('')

  const showAuthMessage = useCallback((message, tone = '') => {
    setAuthMessage(message)
    setAuthMessageTone(tone)
  }, [])

  const clearSession = useCallback(() => {
    clearStoredSession()
    setTokens(null)
    setProfile(null)
  }, [])

  const loadSessions = useCallback(async (accessToken, isActive = () => true) => {
    if (!accessToken) return
    setSessionsLoading(true)
    setSessionsError('')
    try {
      const result = await getSessions(accessToken)
      if (isActive()) setSessions(orderSessions(result.sessions || []))
    } catch (error) {
      if (isActive()) setSessionsError(error.status === 401 ? '登录状态已过期，请重新登录。' : '暂时无法读取会话列表。')
    } finally {
      if (isActive()) setSessionsLoading(false)
    }
  }, [])

  useEffect(() => {
    getHealth().then(() => setApiState('online')).catch(() => setApiState('offline'))
  }, [])

  useEffect(() => {
    if (!sessionReady || !tokens) return undefined
    let cancelled = false
    void Promise.resolve().then(() => {
      if (!cancelled) return loadSessions(tokens.access_token, () => !cancelled)
      return undefined
    })
    return () => { cancelled = true }
  }, [loadSessions, sessionReady, tokens])

  useEffect(() => {
    if (!storedSession) return undefined
    let cancelled = false
    void restoreStoredSession(storedSession).then(({ tokens: restoredTokens, profile: restoredProfile, error }) => {
      if (cancelled) return
      if (error?.status === 401) {
        clearSession()
        showAuthMessage('登录状态已失效，请重新登录。', 'error')
      } else {
        setTokens(restoredTokens)
        setProfile(restoredProfile)
        storeSession(restoredTokens, restoredProfile)
        if (error) {
          showAuthMessage(restoredTokens.refresh_token !== storedSession.tokens.refresh_token
            ? 'Token 已续期，但用户资料暂时无法刷新。'
            : '暂时无法验证当前会话，请检查网络后重试。', 'warning')
        }
      }
    }).finally(() => {
      if (!cancelled) setSessionReady(true)
    })
    return () => { cancelled = true }
  }, [clearSession, showAuthMessage, storedSession])

  const syncProfile = async (activeTokens, fallbackProfile, successMessage, failureMessage) => {
    let nextProfile = fallbackProfile
    let failed = false
    try {
      nextProfile = await getProfile(activeTokens.access_token)
    } catch {
      failed = true
    }
    setProfile(nextProfile)
    storeSession(activeTokens, nextProfile)
    showAuthMessage(failed ? failureMessage : successMessage, failed ? 'warning' : successMessage ? 'success' : '')
  }

  const handleLogin = async (event) => {
    event.preventDefault()
    setAuthBusy(true)
    showAuthMessage('正在验证凭证…')
    try {
      const result = await login(email, password)
      setTokens(result)
      setProfile({ email })
      storeSession(result, { email })
      setPassword('')
      window.location.hash = '#/'
      await syncProfile(result, { email }, '', '已登录，但暂时无法读取用户资料。')
    } catch (error) {
      showAuthMessage(error instanceof Error ? error.message : '登录失败', 'error')
    } finally {
      setAuthBusy(false)
    }
  }

  const handleRefresh = async () => {
    if (!tokens) return
    setAuthBusy(true)
    try {
      const nextTokens = await refresh(tokens.refresh_token)
      setTokens(nextTokens)
      storeSession(nextTokens, profile)
      await syncProfile(nextTokens, profile, 'Token 已续期，旧 Refresh Token 已失效。', 'Token 已续期，但用户资料暂时无法刷新。')
    } catch (error) {
      showAuthMessage(error instanceof Error ? error.message : '刷新失败，请重新登录', 'error')
      if (error.status === 401) {
        clearSession()
        window.location.hash = '#/login'
      }
    } finally {
      setAuthBusy(false)
    }
  }

  const handleLogout = async (allSessions = false) => {
    if (!tokens) return
    setAuthBusy(true)
    try {
      if (allSessions) await logoutAll(tokens.access_token)
      else await logout(tokens.access_token)
      clearSession()
      showAuthMessage(allSessions ? '当前用户的全部会话已撤销。' : '当前会话已撤销。')
      window.location.hash = '#/login'
    } catch (error) {
      showAuthMessage(error instanceof Error ? error.message : '登出失败', 'error')
    } finally {
      setAuthBusy(false)
    }
  }

  if (tokens && !sessionReady) {
    return <main className="session-restore"><span />正在恢复登录状态…</main>
  }

  if (!tokens) {
    return <LoginPage
      email={email}
      password={password}
      onEmailChange={setEmail}
      onPasswordChange={setPassword}
      onSubmit={handleLogin}
      busy={authBusy}
      message={authMessage}
    />
  }

  return (
    <main className="security-dashboard">
      <header className="dashboard-header">
        <div className="dashboard-brand"><span>auth<span>.</span>security</span><small>认证控制台</small></div>
        <div className="dashboard-header-info">
          <div className={`connection-pill ${apiState}`}><i />{apiState === 'online' ? '后端已连接' : apiState === 'checking' ? '连接检查中' : '后端未连接'}</div>
          <div className="dashboard-header-actions">
            <button type="button" onClick={() => void handleLogout()} disabled={authBusy}>退出</button>
            <button type="button" onClick={() => void handleLogout(true)} disabled={authBusy}>退出全部</button>
          </div>
        </div>
      </header>

      <div className="dashboard-content">
        <section className="dashboard-intro">
          <div>
            <h1>会话管理</h1>
            <span>{profile?.email || '当前账号'}</span>
          </div>
        </section>

        <section className="dashboard-session-list" aria-labelledby="sessions-heading">
          <div className="dashboard-section-heading">
            <div><h2 id="sessions-heading">活动会话 <span className="session-count">{sessions.length}</span></h2><p>已登录的设备和会话状态。</p></div>
            <button type="button" onClick={() => void loadSessions(tokens.access_token)} disabled={sessionsLoading}>{sessionsLoading ? '加载中…' : '刷新列表'}</button>
          </div>
          <p className={`dashboard-message ${authMessageTone}`} role="status" aria-live="polite">{authMessage}</p>
          {sessionsError && <p className="sessions-error" role="status">{sessionsError}</p>}
          {!sessionsError && !sessionsLoading && sessions.length === 0 && <p className="sessions-empty">当前没有活动会话。</p>}
          <div className="sessions-grid">
            {sessions.map((session) => (
              <article className={`session-card${session.current ? ' current' : ''}`} key={session.sessionId}>
                <div className="session-card-heading">
                  <strong>{session.device || '未知设备'}</strong>
                  {session.current && <span>当前会话</span>}
                  {session.current && <button className="dashboard-refresh" type="button" onClick={() => void handleRefresh()} disabled={authBusy}>{authBusy ? '续期中…' : '续期'} <span>↻</span></button>}
                </div>
                <dl>
                  <div><dt>IP 地址</dt><dd>{session.clientIp || '未知'}</dd></div>
                  <div><dt>登录时间</dt><dd>{formatDate(session.createdAt)}</dd></div>
                  <div><dt>最近活动</dt><dd>{formatDate(session.lastUsedAt)}</dd></div>
                  <div><dt>会话到期</dt><dd>{formatDate(session.expiresAt)}</dd></div>
                </dl>
                <details className="session-extra">
                  <summary>更多会话信息</summary>
                  <dl>
                    <div><dt>会话 ID</dt><dd>{session.sessionId}</dd></div>
                    <div><dt>会话最晚到期</dt><dd>{formatDate(session.absoluteExpiresAt)}</dd></div>
                    {session.current && <div><dt>认证方式</dt><dd>{formatAuthenticationMethods(profile?.authenticationMethods)}</dd></div>}
                    {session.current && <div><dt>Access Token 有效期</dt><dd>{tokens.expires_in} 秒</dd></div>}
                    {session.current && <div className="session-refresh-token"><dt>Refresh Token（演示）</dt><dd>{tokens.refresh_token}</dd></div>}
                  </dl>
                </details>
              </article>
            ))}
          </div>
        </section>

        <footer className="dashboard-footer">演示项目会显示完整 Refresh Token，请勿用于生产环境。Token 存在当前标签页的 sessionStorage 中以支持刷新恢复；关闭标签页后清除。</footer>
      </div>
    </main>
  )
}
