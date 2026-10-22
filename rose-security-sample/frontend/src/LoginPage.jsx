export default function LoginPage({ email, password, onEmailChange, onPasswordChange, onSubmit, busy, message, mfaChallenge, mfaMethod, onMfaMethodChange, mfaCode, onMfaCodeChange, onMfaSubmit }) {
  return (
    <main className="login-page">
      <div className="login-layout">
        <section className="login-intro" aria-label="认证能力介绍">
          <h1>让登录清晰，<br /><em>让会话可控。</em></h1>
          <p>这是一个面向前后端分离应用的认证示例。登录后进入受保护的控制台，查看 Token 会话状态并体验续期与登出。</p>
          <ul className="login-features">
            <li><span className="feature-check">✓</span><span><strong>邮箱与密码</strong><small>登录后由后端签发 Access Token 和 Refresh Token</small></span></li>
            <li><span className="feature-check">✓</span><span><strong>会话管理</strong><small>演示续期轮换、单会话登出和全部会话撤销</small></span></li>
            <li><span className="feature-check">✓</span><span><strong>多因素验证</strong><small>支持身份验证器、邮件验证码与通行密钥</small></span></li>
          </ul>
          <p className="login-public-note">未登录时只显示本介绍和登录入口；用户资料及会话控制仅登录后可见。</p>
        </section>
        <section className="login-card">
          <h2>{mfaChallenge ? '验证身份' : '欢迎回来'}</h2>
          <p>{mfaChallenge ? (mfaMethod === 'webauthn' ? '使用已绑定的通行密钥完成验证' : mfaMethod === 'email' ? '从邮箱中查看验证码并完成登录' : '输入身份验证器当前显示的 6 位验证码') : '登录以访问认证与会话控制台'}</p>
          {mfaChallenge ? (
            <form className="auth-form" onSubmit={onMfaSubmit}>
              {mfaChallenge.methods?.length > 1 && <label>验证方式<select value={mfaMethod} onChange={(event) => onMfaMethodChange(event.target.value)}>{mfaChallenge.methods.map((method) => <option key={method} value={method}>{method === 'email' ? '邮箱验证码' : method === 'totp' ? '身份验证器' : method === 'webauthn' ? '通行密钥' : method}</option>)}</select></label>}
              {mfaMethod !== 'webauthn' && <label>{mfaMethod === 'email' ? '邮箱验证码' : '身份验证器验证码'}<input inputMode="numeric" pattern="[0-9]{6}" maxLength="6" value={mfaCode} onChange={(event) => onMfaCodeChange(event.target.value.replace(/\D/g, '').slice(0, 6))} autoComplete="one-time-code" required /></label>}
              <button className="auth-primary" type="submit" disabled={busy || (mfaMethod !== 'webauthn' && mfaCode.length !== 6)}><span>{busy ? '正在验证…' : mfaMethod === 'webauthn' ? '使用通行密钥验证' : '完成验证'}</span><span className="login-button-arrow" aria-hidden="true">→</span></button>
              <button className="auth-secondary" type="button" onClick={() => window.location.reload()} disabled={busy}>返回登录</button>
            </form>
          ) : (
            <form className="auth-form" onSubmit={onSubmit}>
              <label>邮箱地址<input type="email" placeholder="name@example.com" value={email} onChange={(event) => onEmailChange(event.target.value)} autoComplete="username" required /></label>
              <label>密码<input type="password" placeholder="请输入密码" value={password} onChange={(event) => onPasswordChange(event.target.value)} autoComplete="current-password" required /></label>
              <button className="auth-primary" type="submit" disabled={busy}><span>{busy ? '正在登录…' : '登录控制台'}</span><span className="login-button-arrow" aria-hidden="true">→</span></button>
            </form>
          )}
          <p className="auth-message" role="status" aria-live="polite">{message}</p>
          <div className="login-demo-account"><span className="login-demo-dot" /><span>演示账号</span><code>demo@example.test</code><b>/</b><code>password</code></div>
          <small className="auth-storage-note">登录状态保存在当前标签页，刷新页面后可恢复；关闭标签页后清除。</small>
        </section>
      </div>
    </main>
  )
}
