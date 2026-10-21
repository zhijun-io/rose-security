export default function LoginPage({ email, password, onEmailChange, onPasswordChange, onSubmit, busy, message }) {
  return (
    <main className="login-page">
      <div className="login-layout">
        <section className="login-intro" aria-label="认证能力介绍">
          <h1>让登录清晰，<br /><em>让会话可控。</em></h1>
          <p>这是一个面向前后端分离应用的认证示例。登录后进入受保护的控制台，查看 Token 会话状态并体验续期与登出。</p>
          <ul className="login-features">
            <li><span className="feature-check">✓</span><span><strong>邮箱与密码</strong><small>登录后由后端签发 Access Token 和 Refresh Token</small></span></li>
            <li><span className="feature-check">✓</span><span><strong>会话管理</strong><small>演示续期轮换、单会话登出和全部会话撤销</small></span></li>
            <li><span className="feature-pending">·</span><span><strong>扩展能力</strong><small>MFA 与 OAuth2/OIDC 后续接入</small></span></li>
          </ul>
          <p className="login-public-note">未登录时只显示本介绍和登录入口；用户资料及会话控制仅登录后可见。</p>
        </section>
        <section className="login-card">
          <div className="login-card-heading">
            <span className="login-card-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none"><path d="M12 3.5 19 6v5.1c0 4.5-2.8 7.7-7 9.6-4.2-1.9-7-5.1-7-9.6V6l7-2.5Z" /><path d="m9 11.8 2 2 4-4.1" /></svg>
            </span>
            <span className="login-secure-label"><i />安全登录</span>
          </div>
          <h2>欢迎回来</h2>
          <p>登录以访问认证与会话控制台</p>
          <form className="auth-form" onSubmit={onSubmit}>
            <label>邮箱地址<input type="email" placeholder="name@example.com" value={email} onChange={(event) => onEmailChange(event.target.value)} autoComplete="username" required /></label>
            <label>密码<input type="password" placeholder="请输入密码" value={password} onChange={(event) => onPasswordChange(event.target.value)} autoComplete="current-password" required /></label>
            <button className="auth-primary" type="submit" disabled={busy}><span>{busy ? '正在登录…' : '登录控制台'}</span><span className="login-button-arrow" aria-hidden="true">→</span></button>
          </form>
          <p className="auth-message" role="status" aria-live="polite">{message}</p>
          <div className="login-demo-account"><span className="login-demo-dot" /><span>演示账号</span><code>demo@example.test</code><b>/</b><code>password</code></div>
          <small className="auth-storage-note">登录状态保存在当前标签页，刷新页面后可恢复；关闭标签页后清除。</small>
        </section>
      </div>
    </main>
  )
}
