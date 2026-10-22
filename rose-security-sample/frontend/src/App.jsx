import { useCallback, useEffect, useState } from 'react'
import { getHealth } from './services/healthClient.js'
import { beginEmailEnrollment, beginEmailRemoval, beginTotpEnrollment, beginWebAuthnLogin, beginWebAuthnRegistration, beginWebAuthnRemoval, completeWebAuthnRegistration, completeWebAuthnRemoval, confirmEmailEnrollment, confirmEmailRemoval, confirmTotpEnrollment, getProfile, getSessions, getTotpStatus, login, logout, logoutAll, refresh, removeTotp, verifyMfaLogin } from './services/authClient.js'
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

function decodeBase64Url(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
  const binary = window.atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='))
  return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer
}

function encodeBase64Url(value) {
  const bytes = new Uint8Array(value)
  let binary = ''
  bytes.forEach((byte) => { binary += String.fromCharCode(byte) })
  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function credentialJson(credential) {
  const response = credential.response
  const result = {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      ...(response.attestationObject ? { attestationObject: encodeBase64Url(response.attestationObject) } : {}),
      ...(response.authenticatorData ? { authenticatorData: encodeBase64Url(response.authenticatorData) } : {}),
      ...(response.signature ? { signature: encodeBase64Url(response.signature) } : {}),
      ...(response.userHandle ? { userHandle: encodeBase64Url(response.userHandle) } : {}),
      ...(response.getTransports ? { transports: response.getTransports() } : {}),
    },
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment,
  }
  return result
}

function webAuthnOptions(options, ceremony) {
  const publicKey = { ...options }
  publicKey.challenge = decodeBase64Url(publicKey.challenge)
  if (ceremony === 'create') {
    publicKey.user = { ...publicKey.user, id: decodeBase64Url(publicKey.user.id) }
    publicKey.excludeCredentials = publicKey.excludeCredentials?.map((item) => ({ ...item, id: decodeBase64Url(item.id) }))
  } else {
    publicKey.allowCredentials = publicKey.allowCredentials?.map((item) => ({ ...item, id: decodeBase64Url(item.id) }))
  }
  return publicKey
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
  const [mfaChallenge, setMfaChallenge] = useState(null)
  const [mfaMethod, setMfaMethod] = useState('totp')
  const [mfaCode, setMfaCode] = useState('')
  const [totpStatus, setTotpStatus] = useState(null)
  const [totpEnrollment, setTotpEnrollment] = useState(null)
  const [totpCode, setTotpCode] = useState('')
  const [totpRemovalCode, setTotpRemovalCode] = useState('')
  const [emailEnrollment, setEmailEnrollment] = useState(null)
  const [emailRemoval, setEmailRemoval] = useState(null)
  const [emailCode, setEmailCode] = useState('')
  const [emailRemovalCode, setEmailRemovalCode] = useState('')

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
    if (!sessionReady || !tokens) return undefined
    let cancelled = false
    getTotpStatus(tokens.access_token).then((status) => {
      if (!cancelled) setTotpStatus(status)
    }).catch(() => {
      if (!cancelled) setTotpStatus(null)
    })
    return () => { cancelled = true }
  }, [sessionReady, tokens])

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
      if (result.status === 'mfa_required') {
        setMfaChallenge(result)
        setMfaMethod(result.methods?.includes('totp') ? 'totp' : result.methods?.[0] || 'email')
        setMfaCode('')
        showAuthMessage('主凭证已验证，请完成 MFA。')
        return
      }
      await completeLogin(result)
    } catch (error) {
      showAuthMessage(error instanceof Error ? error.message : '登录失败', 'error')
    } finally {
      setAuthBusy(false)
    }
  }

  const completeLogin = async (result) => {
      setTokens(result)
      setProfile({ email })
      storeSession(result, { email })
      setPassword('')
      setMfaChallenge(null)
      setMfaCode('')
      window.location.hash = '#/'
      await syncProfile(result, { email }, '', '已登录，但暂时无法读取用户资料。')
  }

  const handleMfaLogin = async (event) => {
    event.preventDefault()
    if (!mfaChallenge) return
    setAuthBusy(true)
    try {
      let proof = mfaCode
      if (mfaMethod === 'webauthn') {
        if (!navigator.credentials) throw new Error('当前浏览器不支持 WebAuthn。')
        const challenge = await beginWebAuthnLogin(mfaChallenge.transaction_token)
        const credential = await navigator.credentials.get({ publicKey: webAuthnOptions(challenge.publicKey, 'get') })
        if (!credential) throw new Error('未完成通行密钥验证。')
        proof = JSON.stringify({ challenge_token: challenge.challengeToken, credential: credentialJson(credential) })
      }
      const result = await verifyMfaLogin(mfaChallenge.transaction_token, mfaMethod, proof)
      await completeLogin(result)
    } catch (error) {
      showAuthMessage(error instanceof Error ? error.message : '验证码无效或已过期。', 'error')
    } finally {
      setAuthBusy(false)
    }
  }

  const handleBeginTotp = async () => {
    setAuthBusy(true)
    try {
      setTotpEnrollment(await beginTotpEnrollment(tokens.access_token))
      setTotpCode('')
      showAuthMessage('')
    } catch (error) {
      showAuthMessage(error.message || '无法开始绑定 TOTP。', 'error')
    } finally {
      setAuthBusy(false)
    }
  }

  const handleConfirmTotp = async (event) => {
    event.preventDefault()
    setAuthBusy(true)
    try {
      await confirmTotpEnrollment(tokens.access_token, totpCode)
      setTotpEnrollment(null)
      setTotpCode('')
      setTotpStatus((status) => ({ ...status, totpEnrolled: true }))
      showAuthMessage('TOTP 已绑定；当前会话保持有效，之后登录需要验证码。', 'success')
    } catch (error) {
      showAuthMessage(error.message || '验证码无效或绑定已过期。', 'error')
    } finally {
      setAuthBusy(false)
    }
  }

  const handleBindWebAuthn = async () => {
    setAuthBusy(true)
    try {
      if (!navigator.credentials) throw new Error('当前浏览器不支持 WebAuthn。')
      const challenge = await beginWebAuthnRegistration(tokens.access_token)
      const credential = await navigator.credentials.create({ publicKey: webAuthnOptions(challenge.publicKey, 'create') })
      if (!credential) throw new Error('未完成通行密钥注册。')
      await completeWebAuthnRegistration(tokens.access_token, challenge.challengeToken, credentialJson(credential), '浏览器通行密钥')
      setTotpStatus(await getTotpStatus(tokens.access_token))
      showAuthMessage('通行密钥已绑定；当前会话保持有效。', 'success')
    } catch (error) {
      showAuthMessage(error.message || '无法绑定通行密钥。', 'error')
    } finally {
      setAuthBusy(false)
    }
  }

  const handleRemoveWebAuthn = async (credentialId) => {
    setAuthBusy(true)
    try {
      if (!navigator.credentials) throw new Error('当前浏览器不支持 WebAuthn。')
      const challenge = await beginWebAuthnRemoval(tokens.access_token, credentialId)
      const credential = await navigator.credentials.get({ publicKey: webAuthnOptions(challenge.publicKey, 'get') })
      if (!credential) throw new Error('未完成通行密钥验证。')
      await completeWebAuthnRemoval(tokens.access_token, challenge.challengeToken, credentialId, credentialJson(credential))
      const status = await getTotpStatus(tokens.access_token)
      setTotpStatus(status)
      showAuthMessage('通行密钥已移除；当前会话保持有效。', 'success')
    } catch (error) {
      showAuthMessage(error.message || '无法移除通行密钥。', 'error')
    } finally {
      setAuthBusy(false)
    }
  }

  const handleRemoveTotp = async (event) => {
    event.preventDefault()
    setAuthBusy(true)
    try {
      await removeTotp(tokens.access_token, totpRemovalCode)
      setTotpRemovalCode('')
      setTotpStatus((status) => ({ ...status, totpEnrolled: false }))
      showAuthMessage('TOTP 已移除；当前会话保持有效。之后登录不再要求该方式。', 'success')
    } catch (error) {
      showAuthMessage(error.message || '验证码无效，无法移除 TOTP。', 'error')
    } finally {
      setAuthBusy(false)
    }
  }

  const handleBeginEmailEnrollment = async () => {
    setAuthBusy(true)
    try {
      setEmailEnrollment(await beginEmailEnrollment(tokens.access_token))
      setEmailCode('')
      showAuthMessage('')
    } catch (error) {
      showAuthMessage(error.message || '无法开始绑定邮箱 MFA。', 'error')
    } finally {
      setAuthBusy(false)
    }
  }

  const handleConfirmEmailEnrollment = async (event) => {
    event.preventDefault()
    setAuthBusy(true)
    try {
      await confirmEmailEnrollment(tokens.access_token, emailEnrollment.challenge_token, emailCode)
      setEmailEnrollment(null)
      setEmailCode('')
      setTotpStatus((status) => ({ ...status, emailEnabled: true }))
      showAuthMessage('邮箱 MFA 已启用。', 'success')
    } catch (error) {
      showAuthMessage(error.message || '验证码无效或绑定已过期。', 'error')
    } finally {
      setAuthBusy(false)
    }
  }

  const handleBeginEmailRemoval = async () => {
    setAuthBusy(true)
    try {
      setEmailRemoval(await beginEmailRemoval(tokens.access_token))
      setEmailRemovalCode('')
      showAuthMessage('')
    } catch (error) {
      showAuthMessage(error.message || '无法开始移除邮箱 MFA。', 'error')
    } finally {
      setAuthBusy(false)
    }
  }

  const handleConfirmEmailRemoval = async (event) => {
    event.preventDefault()
    setAuthBusy(true)
    try {
      await confirmEmailRemoval(tokens.access_token, emailRemoval.challenge_token, emailRemovalCode)
      setEmailRemoval(null)
      setEmailRemovalCode('')
      setTotpStatus((status) => ({ ...status, emailEnabled: false }))
      showAuthMessage('邮箱 MFA 已移除。', 'success')
    } catch (error) {
      showAuthMessage(error.message || '验证码无效或已过期。', 'error')
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
      mfaChallenge={mfaChallenge}
      mfaMethod={mfaMethod}
      onMfaMethodChange={setMfaMethod}
      mfaCode={mfaCode}
      onMfaCodeChange={setMfaCode}
      onMfaSubmit={handleMfaLogin}
    />
  }

  return (
    <main className="security-dashboard">
      <header className="dashboard-header">
        <div className="dashboard-brand"><span>Rose Security</span><small>认证控制台</small></div>
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
        <p className={`dashboard-message ${authMessageTone}`} role="status" aria-live="polite">{authMessage}</p>

        <section className="dashboard-session-list totp-panel" aria-labelledby="totp-heading">
          <div className="dashboard-section-heading">
            <div><h2 id="totp-heading">TOTP 验证</h2><p>{totpStatus?.totpEnrolled ? 'TOTP 已绑定；下一次登录需要验证码。' : '绑定身份验证器后，下次登录需要验证码。'}</p></div>
            {!totpStatus?.totpEnrolled && <button type="button" onClick={() => void handleBeginTotp()} disabled={authBusy || Boolean(totpEnrollment || emailEnrollment || emailRemoval)}>绑定 TOTP</button>}
          </div>
          {totpEnrollment && (
            <form className="totp-enrollment" onSubmit={handleConfirmTotp}>
              <p>在身份验证器中手动添加密钥：</p>
              <code>{totpEnrollment.secret}</code>
              <label>输入应用显示的 6 位验证码<input inputMode="numeric" pattern="[0-9]{6}" maxLength="6" value={totpCode} onChange={(event) => setTotpCode(event.target.value.replace(/\D/g, '').slice(0, 6))} autoComplete="one-time-code" required /></label>
              <button className="dashboard-refresh" type="submit" disabled={authBusy || totpCode.length !== 6}>确认绑定</button>
            </form>
          )}
          {totpStatus?.totpEnrolled && (
            <form className="totp-enrollment" onSubmit={handleRemoveTotp}>
              <p>输入身份验证器当前的验证码以移除 TOTP。</p>
              <label>TOTP 验证码<input inputMode="numeric" pattern="[0-9]{6}" maxLength="6" value={totpRemovalCode} onChange={(event) => setTotpRemovalCode(event.target.value.replace(/\D/g, '').slice(0, 6))} autoComplete="one-time-code" required /></label>
              <button className="totp-remove" type="submit" disabled={authBusy || totpRemovalCode.length !== 6}>验证并移除 TOTP</button>
            </form>
          )}
        </section>

        <section className="dashboard-session-list totp-panel" aria-labelledby="email-mfa-heading">
          <div className="dashboard-section-heading">
            <div><h2 id="email-mfa-heading">邮箱验证</h2><p>{totpStatus?.emailEnabled ? '邮箱 MFA 已启用。' : '通过当前账号邮箱接收一次性验证码。'}</p></div>
            {!totpStatus?.emailEnabled && <button type="button" onClick={() => void handleBeginEmailEnrollment()} disabled={authBusy || Boolean(totpEnrollment || emailEnrollment || emailRemoval)}>启用邮箱 MFA</button>}
            {totpStatus?.emailEnabled && !emailRemoval && <button className="totp-remove" type="button" onClick={() => void handleBeginEmailRemoval()} disabled={authBusy || Boolean(totpEnrollment || emailEnrollment || emailRemoval)}>移除邮箱 MFA</button>}
          </div>
          {emailEnrollment && (
            <form className="totp-enrollment" onSubmit={handleConfirmEmailEnrollment}>
              <p>验证码已发送到 {profile?.email || '当前账号邮箱'}，请完成验证以启用邮箱 MFA。</p>
              <label>邮箱验证码<input inputMode="numeric" pattern="[0-9]{6}" maxLength="6" value={emailCode} onChange={(event) => setEmailCode(event.target.value.replace(/\D/g, '').slice(0, 6))} autoComplete="one-time-code" required /></label>
              <button className="dashboard-refresh" type="submit" disabled={authBusy || emailCode.length !== 6}>验证并启用</button>
            </form>
          )}
          {emailRemoval && (
            <form className="totp-enrollment" onSubmit={handleConfirmEmailRemoval}>
              <p>验证码已发送到 {profile?.email || '当前账号邮箱'}，验证后将移除邮箱 MFA。</p>
              <label>邮箱验证码<input inputMode="numeric" pattern="[0-9]{6}" maxLength="6" value={emailRemovalCode} onChange={(event) => setEmailRemovalCode(event.target.value.replace(/\D/g, '').slice(0, 6))} autoComplete="one-time-code" required /></label>
              <button className="totp-remove" type="submit" disabled={authBusy || emailRemovalCode.length !== 6}>验证并移除</button>
            </form>
          )}
        </section>

        <section className="dashboard-session-list totp-panel" aria-labelledby="webauthn-heading">
          <div className="dashboard-section-heading">
            <div><h2 id="webauthn-heading">通行密钥</h2><p>使用设备验证器完成抗钓鱼认证。</p></div>
            <button type="button" onClick={() => void handleBindWebAuthn()} disabled={authBusy}>添加通行密钥</button>
          </div>
          {totpStatus?.webauthnCredentials?.map((credential) => (
            <div className="session-card-heading" key={credential.id}>
              <strong>{credential.label || '通行密钥'}</strong>
              <button className="totp-remove" type="button" onClick={() => void handleRemoveWebAuthn(credential.id)} disabled={authBusy}>验证并移除</button>
            </div>
          ))}
          {!totpStatus?.webauthnCredentials?.length && <p className="sessions-empty">尚未绑定通行密钥。</p>}
        </section>

        <section className="dashboard-session-list" aria-labelledby="sessions-heading">
          <div className="dashboard-section-heading">
            <div><h2 id="sessions-heading">活动会话 <span className="session-count">{sessions.length}</span></h2><p>已登录的设备和会话状态。</p></div>
            <button type="button" onClick={() => void loadSessions(tokens.access_token)} disabled={sessionsLoading}>{sessionsLoading ? '加载中…' : '刷新列表'}</button>
          </div>
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
