import { useCallback, useEffect, useState } from 'react'
import { getHealth } from './services/healthClient.js'

const modules = [
  { name: '本地邮箱认证', detail: '邮箱凭证验证与本地 JWT 签发', tag: 'CORE', icon: '↗', tone: 'violet' },
  { name: '多因素认证', detail: 'TOTP · Passkey · Email · 恢复凭证', tag: 'OPTIONAL', icon: '⌁', tone: 'blue' },
  { name: 'OAuth2 / OIDC', detail: '第三方登录与本地账号映射', tag: 'OPTIONAL', icon: '◎', tone: 'amber' },
  { name: 'Token 会话', detail: 'Refresh 轮换 · 撤销 · 会话管理', tag: 'CORE', icon: '⟳', tone: 'green' },
]

const stages = [
  { number: '01', name: 'Starter 骨架', state: '进行中', done: true },
  { number: '02', name: 'JWT 与会话', state: '待开发' },
  { number: '03', name: 'MFA 因子', state: '待开发' },
  { number: '04', name: 'OAuth2 / OIDC', state: '待开发' },
]

export default function App() {
  const [apiState, setApiState] = useState('checking')
  const [health, setHealth] = useState(null)
  const [checkedAt, setCheckedAt] = useState(null)

  const checkApi = useCallback(async () => {
    setApiState('checking')
    try {
      setHealth(await getHealth())
      setApiState('online')
    } catch (error) {
      setHealth({ detail: error instanceof Error ? error.message : '请求失败' })
      setApiState('offline')
    } finally {
      setCheckedAt(new Date())
    }
  }, [])

  useEffect(() => {
    const timer = window.setTimeout(() => void checkApi(), 0)
    return () => window.clearTimeout(timer)
  }, [checkApi])

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#top" aria-label="Auth Security 首页">
          <span className="brand-mark"><span /></span>
          <span className="brand-copy"><strong>auth<span>.</span>security</strong><small>STARTER CONSOLE</small></span>
        </a>

        <div className="workspace-label">工作区</div>
        <nav className="side-nav" aria-label="主导航">
          <a className="nav-item active" href="#overview"><span className="nav-icon">▦</span>总览</a>
          <a className="nav-item" href="#modules"><span className="nav-icon">◈</span>认证模块</a>
          <a className="nav-item" href="#connection"><span className="nav-icon">⌘</span>API 连接</a>
          <a className="nav-item" href="#roadmap"><span className="nav-icon">◷</span>实现进度</a>
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-note"><span className="note-dot" />安全边界清晰<br /><small>无业务用户模型 · 无限流模块</small></div>
          <div className="version"><span>开发版本</span><code>0.1.0-SNAPSHOT</code></div>
        </div>
      </aside>

      <main id="top" className="main-content">
        <header className="topbar">
          <div className="breadcrumb"><span>工作区</span><b>/</b><strong>认证基础设施</strong></div>
          <div className="topbar-right">
            <div className={`connection-pill ${apiState}`}><i />{apiState === 'online' ? 'API 已连接' : apiState === 'checking' ? '连接检查中' : 'API 未连接'}</div>
            <div className="avatar">AS</div>
          </div>
        </header>

        <div className="page-wrap">
          <section id="overview" className="hero-row">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" />AUTHENTICATION INFRASTRUCTURE</div>
              <h1>认证与会话<br /><em>一目了然。</em></h1>
              <p className="hero-description">用一个可组合的 Spring Boot Starter，为 API 后端构建可靠的身份认证基础。</p>
            </div>
            <div className="hero-card">
              <div className="hero-card-top"><span className="shield-icon">✦</span><span className="preview-label">项目状态</span><span className="preview-indicator"><i />骨架就绪</span></div>
              <div className="hero-card-title">从可验证的基础开始</div>
              <p>模块结构、自动配置、扩展契约和接入样例已建立。认证流程将按安全边界逐步实现。</p>
              <a className="text-link" href="#roadmap">查看实现计划 <span>↗</span></a>
              <div className="hero-orbit orbit-one" /><div className="hero-orbit orbit-two" />
            </div>
          </section>

          <section className="stats-grid" aria-label="项目摘要">
            <div className="stat-card"><span className="stat-icon purple">⌘</span><div><small>后端框架</small><strong>Spring Boot <b>4.1</b></strong><span>Spring Security 7</span></div><span className="stat-corner">01</span></div>
            <div className="stat-card"><span className="stat-icon mint">◉</span><div><small>认证方式</small><strong>本地邮箱 + OIDC</strong><span>本地签发 API Token</span></div><span className="stat-corner">02</span></div>
            <div className="stat-card"><span className="stat-icon orange">⛨</span><div><small>多因素认证</small><strong>默认关闭</strong><span>用户自选 · 策略可扩展</span></div><span className="stat-corner">03</span></div>
            <div className="stat-card"><span className="stat-icon blue">⇄</span><div><small>会话策略</small><strong>Access + Refresh</strong><span>响应体传递 · 可撤销设计</span></div><span className="stat-corner">04</span></div>
          </section>

          <section id="modules" className="section-block">
            <div className="section-heading"><div><div className="eyebrow muted">CAPABILITIES</div><h2>模块概览</h2></div><span className="section-caption">核心能力与可选集成</span></div>
            <div className="module-grid">
              {modules.map((module) => <article className="module-card" key={module.name}>
                <div className="module-card-top"><span className={`module-icon ${module.tone}`}>{module.icon}</span><span className={`module-tag ${module.tag === 'CORE' ? 'core' : ''}`}>{module.tag}</span></div>
                <h3>{module.name}</h3><p>{module.detail}</p>
                <div className="module-footer"><span className="module-status"><i />接口规划中</span><span className="arrow">↗</span></div>
              </article>)}
            </div>
          </section>

          <section className="lower-grid">
            <div id="connection" className="panel connection-panel">
              <div className="panel-heading"><div><div className="eyebrow muted">LIVE CHECK</div><h2>后端连接</h2></div><button className="refresh-button" onClick={() => void checkApi()} disabled={apiState === 'checking'} aria-label="重新检查 API">↻</button></div>
              <p className="panel-description">通过 Vite 同源代理检查 Spring Boot 示例 API。</p>
              <div className="endpoint-row"><span className="http-method">GET</span><code>/api/sample/health</code><span className={`endpoint-state ${apiState}`}>{apiState === 'online' ? '200 OK' : apiState === 'checking' ? '检查中' : '连接失败'}</span></div>
              <div className="response-box"><div className="response-top"><span><i />响应预览</span><code>{checkedAt ? checkedAt.toLocaleTimeString('zh-CN') : '—'}</code></div><pre>{health ? JSON.stringify(health, null, 2) : '{\n  "status": "等待响应"\n}'}</pre></div>
            </div>

            <div id="roadmap" className="panel roadmap-panel">
              <div className="panel-heading"><div><div className="eyebrow muted">BUILD ROADMAP</div><h2>实现进度</h2></div><span className="progress-count">01 <i>/</i> 05</span></div>
              <div className="progress-track"><span /></div>
              <ol className="roadmap-list">
                {stages.map((stage) => <li className={stage.done ? 'complete' : ''} key={stage.number}><span className="stage-number">{stage.done ? '✓' : stage.number}</span><span className="stage-name">{stage.name}</span><span className="stage-state">{stage.state}</span></li>)}
                <li className="future-stage"><span className="stage-number">05</span><span className="stage-name">存储适配与文档</span><span className="stage-state">待开发</span></li>
              </ol>
            </div>
          </section>

          <footer className="page-footer"><span><b>AUTH SECURITY STARTER</b> · 用清晰的边界构建可信认证</span><span>Java 25&nbsp; / &nbsp;Spring Boot 4.1.1</span></footer>
        </div>
      </main>
    </div>
  )
}
