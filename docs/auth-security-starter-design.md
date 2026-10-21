# Auth Security Spring Boot Starter 设计方案

- 状态：设计基线；第一阶段工程/API 骨架已实现，后续认证能力待实现
- 项目：`auth-security-spring-boot-starter`
- 文档日期：2026-10-21
- 当前项目版本基线：Java 25、Spring Boot 4.1.1、Spring Security 7、Maven（以根 `pom.xml` 为准）

本文将已确认需求、推荐实现、部署配置和仍需产品决策的事项分开记录。该仓库是独立新项目，不继承其他本地项目的领域模型或安全策略。

## 1. 目标与边界

交付一个面向前后端分离后端的可复用认证与会话 Starter，包含本地邮箱登录、自签 JWT、可撤销 Refresh Token 会话、可选 MFA、OAuth2/OIDC 第三方客户端登录，以及 JDBC/Redis 可选存储适配。

Starter 提供安全协议和基础设施扩展点，不拥有业务用户模型、用户注册、组织/租户、角色权限、审批或业务审计语义。OAuth2/OIDC 仅作为客户端登录接入第三方身份提供方；不实现授权服务器、不签发第三方 OAuth 授权码，也不把第三方 Token 当作本系统 API Token。

**限流不属于本项目范围。** 不实现或引入限流依赖、限流存储、限流配置、限流扩展点或限流分支。协议自身必需的验证码尝试上限、挑战有效期和一次性消费属于凭证安全约束，不是通用限流功能。

## 2. 已确认需求、推荐方案与假设

| 项目 | 结论 | 属性 |
|---|---|---|
| 工程 | 从零开始的独立 Maven 多模块项目 | 已确认 |
| Java / Boot / Security | Java 25、Boot 4.1.1、Security 7；实现时核对模块 API 和依赖 | 当前项目基线，非所有消费应用的兼容承诺 |
| 本地登录标识 | 邮箱 | 已确认 |
| OAuth 账号关联 | 参考 ThingsBoard，基于邮箱关联 | 已确认方向；邮箱可信度及冲突细则见待决事项 |
| MFA | 默认关闭；启用时用户可选择并绑定可用方式；不使用 Security 7 内建 MFA 特性 | 已确认 |
| MFA 类型 | TOTP、WebAuthn、Email、恢复码、BIP-39 12 词助记词、EVM 钱包 | 已确认类型；钱包协议和助记词语义需按下文约束 |
| OAuth | Spring Security OAuth2 Client/OIDC Client；OAuth 注册信息可由数据库运行时提供 | 已确认 |
| MFA/OAuth 配置 | 数据库存储和运行时配置，不要求从 YAML 配置每个因子或 IdP | 已确认；存储适配为可选模块 |
| Token | 短期 Access JWT + 长期 Refresh Token；Refresh Token 通过响应体传输；提供 JDBC/Redis 可选适配 | 已确认 |
| 认证端点实现 | 登录、登出、刷新经 Spring Security Filter Chain，不新增 MVC Controller | 已确认 |
| API 错误 | RFC 9457 `ProblemDetail` | 已确认 |
| 项目模块名 | 父工程 `auth-security-spring-boot-starter-parent`；接入用依赖模块 `auth-security-spring-boot-starter` | 已确认。两者需区分以避免 Maven GAV 重复 |

### 推荐默认值（可配置，不是不可变协议承诺）

- Access Token：RS256、10 分钟；Refresh Token：随机不透明值、14 天滑动或固定到期时间由产品配置选择。JWT 中包含 `iss`、`aud`、`sub`、`jti`、`iat`、`nbf`、`exp` 和认证方法/时间声明，不内置角色或租户含义。
- Refresh Token 只存储哈希，放在服务端会话家族记录中，使用时原子轮换；检测到旧 Token 再次使用则撤销整个家族。
- 待完成 MFA 状态采用服务端短时、不透明、一次性挑战；它不能作为 API Access Token 使用。
- 浏览器客户端默认将 Access Token 只保存在内存中，通过 `Authorization: Bearer` 发送；不要将长期凭证放入 `localStorage`。
- OAuth 首次登录不自动创建业务用户。只有按配置的邮箱映射策略成功匹配已有用户后，才创建 `(issuer, subject)` 外部身份关联。
- 助记词采用 BIP-39 英文词表、12 词，并由应用侧预先生成后交给用户；作为登录/账号恢复凭证，不用作 MFA 因子、TOTP 秘钥或钱包私钥。

## 3. 待决定事项

这些事项不阻止先实现模块骨架和安全接口，但在发布可互操作的功能前必须明确。

| 事项 | 推荐选项 | 影响 / 需要确认 |
|---|---|---|
| 发布 `groupId` 与版本策略 | 暂用生成项目 `dev.authstarter`，发布前换成组织拥有的坐标；语义化版本 | 当前 `groupId` 只是脚手架值，不应未经确认发布 |
| JWT 密钥部署 | RSA 私钥由 KMS/Vault/应用 `SigningKeyProvider` 提供；验证公钥支持 `kid` 多键 | 需确定部署环境、KMS 接口和签名权限边界 |
| `iss`、`aud` 和 Token TTL | 每环境显式设置；Access 短期、Refresh 中长期 | API 消费方必须校验同一发行者和受众；配置缺失时生产启动失败 |
| Refresh 生命周期 | 推荐绝对期限 + 可选滑动期限、家族记录和单次轮换 | 确认是否采用滑动续期、会话最大寿命和并发设备政策 |
| MFA 策略 | 默认关闭；启用后允许用户选择并绑定；应用策略可要求特定用户/操作完成 MFA | 需定义“启用后、用户尚未绑定因子”时是否强制注册。建议默认密码登录成功但标记待注册，仅敏感策略要求时拦截 |
| WebAuthn | 管理员配置 RP ID 和精确 Origin allowlist | RP ID 必须是部署域名的有效域；跨域、反向代理、开发域名需单独配置 |
| 钱包认证 | 仅 EVM；建议 SIWE / EIP-4361，并明确链 ID allowlist | 链 ID、钱包签名兼容范围、地址规范化、是否接受合约钱包/智能账户需确认 |
| 助记词恢复 | 12 词 BIP-39 英文，预生成；用于登录和账号恢复 | 确认谁生成、交付、强制轮换、恢复后是否吊销现有会话。助记词熵等同高价值账户凭证，不具备独立 MFA 因子属性 |
| OAuth 邮箱关联 | 仅在 IdP 明确返回 `email_verified=true` 时自动匹配；持久化 `(iss,sub)`；无已验证邮箱不自动关联 | 确认是否允许人工账号关联、邮箱冲突人工处理、IdP 更换/账号解绑规则；不得仅以当前邮箱重关联既有 `(iss,sub)` |
| 令牌返回与 SPA | Refresh Token 响应体，浏览器内存保存；OAuth 回调使用一次性兑换码再由前端 POST 兑换 | 兑换码 TTL、允许的 SPA 回调 URL allowlist、页面刷新后的恢复体验需产品确认 |
| 会话后端 | 生产环境至少一个共享、支持原子比较与更新的 JDBC 或 Redis 后端 | 确认数据库种类、Redis 可用性目标；多实例即时撤销需要共享查询能力 |
| API 错误约定 | RFC 9457 `ProblemDetail`，Starter 错误类型到 ProblemDetail 的映射可替换 | 业务错误码命名空间、字段扩展与国际化由接入应用确定 |
| 配置管理 API | Starter 提供管理服务/接口，HTTP 管理端点可选或由宿主暴露 | 配置修改的管理员授权和变更审计属于宿主应用；需确定管理 API 是否纳入首版 |

## 4. 模块结构

```text
auth-security-spring-boot-starter/          # 仓库目录
├── pom.xml                                 # 父工程（artifactId: auth-security-spring-boot-starter-parent）
├── auth-security-spring-boot-starter-bom/  # 消费方版本对齐 BOM
├── auth-security-core/                     # 认证、Token、会话、事件、扩展 API；不绑定存储/厂商
├── auth-security-spring-boot-autoconfigure/             # Boot 自动配置、属性、条件装配、HTTP 边界
├── auth-security-spring-boot-starter/                   # 便捷依赖，组合核心自动配置和默认必需依赖
├── auth-security-oauth2-client/             # 可选 OAuth2/OIDC 客户端登录适配
├── auth-security-mfa-core/                   # MFA 策略、因子 SPI、挑战状态机
├── auth-security-mfa-standard/               # 可选 TOTP、Email、恢复码、BIP-39 适配
├── auth-security-mfa-webauthn/               # 可选 WebAuthn / Passkey 适配
├── auth-security-mfa-wallet/                 # 可选 EVM 钱包（SIWE 方案待确认）适配
├── auth-security-storage-jdbc/               # 可选 JDBC 持久化适配及迁移脚本
├── auth-security-storage-redis/              # 可选 Redis 原子状态/挑战/会话适配
└── auth-security-sample/                     # 接入示例应用和端到端用法
```

### 依赖边界

- `core` 仅包含 Java/Spring Security 领域契约，不能依赖 JDBC、Redis、邮件、钱包或特定 IdP。
- `autoconfigure` 提供 Boot 4 自动配置元数据；使用 `@AutoConfiguration`、经过验证的 `@ConfigurationProperties`、`@ConditionalOnClass`、`@ConditionalOnProperty`、`@ConditionalOnMissingBean`。依赖缺少时应清楚失败或关闭能力，不能静默降级为不安全模式。
- `starter` 只组合默认核心依赖，不强制引入 JDBC、Redis、WebAuthn 或 EVM 库。消费者按需追加集成模块。
- 本地登录使用 Spring Security `UserDetailsService`（以邮箱查找主体）、`DaoAuthenticationProvider`、`AuthenticationManager` 和可替换 `PasswordEncoder`；不让接入方再实现一套重复的密码校验器。`UserIdentityMapper` 仅用于将已认证的 `UserDetails` 映射到宿主的不透明用户 ID 和安全状态。
- 可选存储适配实现公共 Repository/Store 接口；同一部署的会话状态只选一个权威后端，不做无事务双写。
- 自动配置不注册一个无条件兜底、捕获全部流量的 `SecurityFilterChain`。默认仅提供可组合的过滤器、认证器及安全配置组件；如提供默认链，必须由显式属性启用，且以 `@ConditionalOnMissingBean(SecurityFilterChain.class)` 让宿主完全接管。
- 自定义安全链的应用显式集成 JWT Resource Server、认证端点 matcher、ProblemDetail entry point/denied handler；Boot 4/Security 7 使用 lambda DSL。Bearer API 可以无状态并关闭 CSRF；若接受 Cookie，则必须保留 CSRF 防护。
- 登录使用 Spring Security `AuthenticationFilter`、JSON `AuthenticationConverter`、`AuthenticationManager` 和 JSON 成功/失败处理器；登出使用链内建 `LogoutFilter`，接入 family 撤销 `LogoutHandler`；刷新使用只匹配刷新路径的专用认证过滤器/`AuthenticationManager`。这些流程不经过 MVC Controller。OAuth 登录回调由 Spring Security OAuth2 Login 过滤器处理；MFA 验证按同样的链内 filter adapter 暴露。

## 5. 核心扩展接口

建议 API 包围绕端口定义，HTTP DTO 与存储模型分别放在适配模块，不暴露实体。

| 接口建议 | 宿主/适配职责 |
|---|---|
| Spring Security `UserDetailsService` | 宿主按邮箱（username）加载本地用户；Starter 使用 `DaoAuthenticationProvider` / `AuthenticationManager` 校验密码，默认 `PasswordEncoder` 可被宿主 Bean 替换 |
| `UserIdentityMapper` | 将 `UserDetails` 主体映射为不透明 `String userId`、邮箱和安全版本；不引入 Starter 用户实体 |
| `UserSecurityStateProvider` | 提供用户启用状态、凭证/MFA 版本或安全状态变化；账号禁用/凭证变更通知会话失效 |
| `AuthenticatedUser` / `UserSecurityState` | Starter 只使用不透明 `String userId`、规范化邮箱及必要安全状态，不建用户实体或自定义用户 ID 类型 |
| `SigningKeyProvider`、`VerificationKeyProvider` | 外部密钥来源、当前签名键与多 `kid` 验证公钥；禁止默认硬编码密钥 |
| `SessionFamilyStore`、`RefreshTokenStore` | 建立、原子轮换、重放检测、单族/全用户撤销与会话查询 |
| `MfaPolicyProvider`、`MfaCredentialRepository`、`MfaChallengeStore` | 读取运行时策略、加密存取因子凭证、原子消费有期限挑战 |
| `MfaFactorProvider` | 各因子独立提供绑定、确认、挑战、验证、解绑和恢复能力 |
| `SecretProtector` | 使用 KMS/应用提供的数据加密密钥保护 TOTP 等可恢复秘密；支持密钥版本 |
| `EmailChallengeSender` | 应用发送指定用途验证码；核心只产生/验证，不绑定邮件服务 |
| `WalletSignatureVerifier`、`WalletOwnershipPolicy` | 验签、地址归属检查、链与钱包策略；业务钱包归属判断由宿主提供 |
| `OAuthClientRegistrationProvider` | 动态读取 DB 注册并适配 Spring Security `ClientRegistrationRepository` |
| `FederatedIdentityMapper` | `(issuer, subject)` 到不透明 `String userId` 映射、首次关联和冲突决策 |
| `AuthenticationEventPublisher`、`AuthenticationProblemDetailMapper` | 发布不含敏感凭证的事件；宿主定制错误码/ProblemDetail 扩展 |

所有接口均需定义事务/原子性要求、异常分类、超时和安全失败模式。用户认证、会话存储、MFA 凭证存储、密钥签名和动态 OAuth 注册没有实现时，启用相应能力应启动失败，而不是使用内存存储或演示账号顶替生产实现。

## 6. 配置模型与默认端点

### 配置来源

MFA 因子开关、用户 MFA 策略、WebAuthn RP/Origin、EVM 链 allowlist、OAuth Client Registration 等可运行时变更的业务安全配置放在数据库，由 `MfaPolicyProvider`、`OAuthClientRegistrationProvider` 读取。数据库中的 Client Secret 等秘密必须使用外部密钥加密；加密根密钥从 KMS/Vault/宿主 `SecretProtector` 提供，不能与密文同库明文保存。

`@ConfigurationProperties` 仅用于稳定部署参数，例如端点路径、JWT issuer/audience、TTL 上限、外部密钥提供器标识和存储适配选择。MFA 全局策略默认关闭；MFA 因子及策略、OAuth Client Registration 的启用状态由数据库运行时配置提供。不要用 YAML 保存 MFA/OAuth 运行配置或真实密钥。数据库配置需版本化并广播/轮询失效通知，集群中各节点一致应用；OAuth 配置更新时允许进行中的 state/nonce 回调按原注册版本完成或明确失效。

### 建议端点

所有映射可通过 `auth.security.endpoints.*` 配置；某组端点可显式禁用。路由冲突时启动期报告冲突/配置错误，或者由宿主完全关闭相应控制器并自行映射同一应用服务，不应悄悄覆盖宿主业务路由。

| 用途 | 默认路径/方法 |
|---|---|
| 本地邮箱登录 | `POST /api/auth/login` |
| MFA 完成/挑战验证 | `POST /api/auth/mfa/challenges/{challengeId}/verify` |
| 刷新 Token | `POST /api/auth/refresh` |
| 当前会话登出 | `POST /api/auth/logout` |
| 全部会话撤销 | `POST /api/auth/logout-all` |
| 查询会话 | `GET /api/auth/sessions` |
| 撤销指定会话 | `DELETE /api/auth/sessions/{sessionId}` |
| 因子列表/绑定/确认/解绑/恢复码 | `/api/auth/mfa/**` |
| OAuth 登录开始 | `GET /oauth2/authorization/{registrationId}` |
| OAuth 回调 | `GET /login/oauth2/code/{registrationId}` |
| OAuth 一次性兑换 | `POST /api/auth/oauth2/exchange` |
| JWT 公钥 | `GET /.well-known/jwks.json`（可选组件） |

默认 YAML 只包含静态部署参数，不含密钥和 DB 动态配置：

```yaml
auth:
  security:
    enabled: true
    token:
      issuer: ${AUTH_TOKEN_ISSUER}
      audience: ${AUTH_TOKEN_AUDIENCE}
      access-ttl: 10m
      refresh-ttl: 14d
      refresh-absolute-ttl: 30d
      signing-algorithm: RS256
      key-provider: ${AUTH_SIGNING_KEY_PROVIDER}
    session:
      store: jdbc # jdbc 或 redis；由相应适配模块提供
      revoke-access-immediately: true
    endpoints:
      base-path: /api/auth
      login: /login
      refresh: /refresh
      logout: /logout
      logout-all: /logout-all
```

配置类使用 Bean Validation 校验：有效期必须为正且不超过安全上限；启用 Token 签名时 `issuer`、`audience`、key provider 必填； Cookie 模式（若将来加入）必须强制 HTTPS 和精确 Origin。端点路径应检查绝对/相对格式及相互冲突。DB 配置写入则单独通过应用管理服务验证、版本化和审计。

## 7. JWT、Refresh Token 与会话

### 签发和验证

1. 登录主凭证验证成功且无 MFA 待完成时，生成随机 `jti`、会话 family ID 和短期 Access JWT。
2. Access Token 由 `SigningKeyProvider` 当前 RSA 键签名，带 `kid`；API 使用 Spring Security JWT Resource Server 验证签名、算法 allowlist、issuer、audience、时间声明。不要自建 JWT 解析过滤器。
3. Refresh Token 是 CSPRNG 产生的高熵不透明随机值；HTTP 响应体返回，存储仅保存不可逆哈希、family、用户、安全版本、过期时间、轮换状态和必要设备元信息。
4. Refresh 请求在存储事务中验证当前 token 哈希且未使用，再原子标记旧 token 已消费并创建新 token；任一并发请求失败。已消费 token 再次出现属于重放，撤销 family 并发布安全事件。
5. 客户端对刷新请求做 single-flight，避免并发页面/API 请求重复刷新。服务端不为重复刷新宽限返回相同明文 Token。

### 过期、撤销和失效

- Refresh JWT 不采用长期不可撤销自验证形式。Session family 记录是续期和撤销的权威来源。可撤销 opaque Refresh 的代价是每次续期需共享存储；这是可接受的安全/可用性权衡。
- 当前登出撤销当前 family；logout-all 撤销该用户所有 family；会话查询返回不敏感元信息，不能返回完整 Token。
- 禁用用户、密码/主凭证变更、MFA 凭证/恢复信息变更、身份关联撤销和高风险安全事件应通过 `UserSecurityStateProvider` / 事件钩子触发 family 撤销或提升 token version。
- 即时 Access Token 撤销需要每次请求访问共享 denylist/session state 或检查用户安全版本；这会引入延迟和存储故障影响。推荐在严格即时撤销模式下 fail-closed。若只检查签名与过期，撤销上界为 Access TTL，应明确告知宿主。
- 并发会话策略提供 `SessionConcurrencyPolicy` 扩展，但默认不限制会话数；策略是否踢出最旧会话由宿主业务决定。

### 密钥来源、轮换和泄露

禁止代码、示例、默认配置或测试 fixture 带可用于生产的硬编码私钥。生产通过 KMS/Vault/HSM/宿主实现 `SigningKeyProvider`。推荐 RS256，私钥仅签名服务可访问，JWKS 可发布公钥。轮换时先发布新公钥并让验证端可见，再切换签名 `kid`；旧公钥至少保留至最长 Access Token TTL 加时钟偏差和缓存刷新窗口。发现泄露时立刻停止该键签名、从信任集合移除对应 `kid`、强制刷新验证方 JWKS 缓存、撤销受影响会话家族，并按事件范围重新认证。密钥应记录版本和启用/停用时间。

JWKS 适用于多个独立 API 验证服务、边缘网关或密钥轮换不希望分发私钥的部署。单体内部也可直接提供验证器，但接口应保留多键能力。该端点只发布公钥，不发布或暴露签名材料；是否默认启用由 OAuth/API 拓扑决定。

### 前端和跨域

本方案的 Refresh Token 由响应体传递，避免默认跨域 Cookie 与隐式 CSRF 耦合，但 JS 可读长期凭证仍会受 XSS 窃取。SPA 推荐短暂保存在内存、使用 CSP 与严格依赖治理；不要默认 localStorage。若接入方选择 Refresh Cookie，必须另行启用 Secure、HttpOnly、明确 SameSite、精确 CORS `allowCredentials(true)`、CSRF Token/Origin 校验和 TLS；不能认为 CORS 就是 CSRF 防护。Bearer Header 模式使用精确 CORS Origin allowlist、`allowCredentials(false)`，浏览器状态改变请求仍不得从 Cookie 接受身份。

## 8. MFA 状态机与因子

### 策略和阶段状态

全局默认关闭；开启后可用因子由 DB 配置，用户可以自选并绑定。应用通过 `MfaPolicyProvider` 按用户、操作或风险策略要求 MFA。MFA 策略选择、具体用户数据和因子凭证分开存储。用户完成主凭证后若策略要求 MFA，返回受限、短时、单次的 pending challenge；只允许挑战列出的验证操作，任何普通业务 API 均拒绝。验证成功后原子消费挑战并签发完整 Token，记录 `amr`/认证时间。绑定、解绑、恢复等高风险操作应要求近期重新认证/现有因子证明。

用户启用因子时使用独立因子 provider 生命周期：开始绑定 -> 产生待确认凭证 -> 用户证明 possession -> 持久化为 active -> challenge/verify -> unbind/recovery。绑定之前的密钥不可用于认证，解绑或重置必须使有关会话家族失效。失败次数和挑战过期由因子/挑战存储实现；不提供通用限流设施。

因子机密按用途最小化存储：可验证值使用带强盐的哈希；必须恢复原值的 TOTP 秘密使用 `SecretProtector` 加密、密钥版本化、严格访问控制。日志、事件、ProblemDetail 和可观测性中禁止出现密码、TOTP 秘密、OTP、恢复码、助记词、WebAuthn 私密状态和完整 Token。

### 因子规范

| 因子 | 绑定/验证与存储规则 | 默认/外部依赖 |
|---|---|---|
| TOTP | CSPRNG 生成秘密，Base32/`otpauth` QR 仅在绑定期间展示；必须先提交一次有效 OTP 才激活；验证窗口窄且可配置，拒绝已接受时间步重放；秘密加密存储 | `auth-security-mfa-standard` 可选；需 `SecretProtector` 和 MFA Store |
| WebAuthn | 注册和认证都使用一次性 challenge；challenge 绑定 user、操作、RP ID、有效期；校验 clientData origin、challenge、RP ID hash、签名、credential ID/计数器及用户验证要求；使用后作废 | `auth-security-mfa-webauthn` 可选；依赖配置的 RP ID 和精确允许 Origin、持久凭证存储 |
| Email | OTP 与用户、用途、挑战绑定；哈希存储、短时有效、成功一次消费；失败达到 challenge 自身尝试上限即作废；发送通过 `EmailChallengeSender` | 标准扩展模块；接入方提供发信实现、收件邮箱和持久存储 |
| 恢复码 | 高熵随机码，只展示一次；仅保存哈希；成功使用立即原子失效；重新生成时旧码整批失效；全部丢失需应用受控身份恢复流程或人工核验，Starter 不冒充业务审批 | 标准扩展模块；需 MFA Store 和宿主恢复流程 |
| BIP-39 助记词 | 12 个英文 BIP-39 词，系统/应用预先生成并安全交付；只用于用户登录和账号恢复；不导出私钥、不派生钱包、不冒充第二因子；数据库仅存安全验证器，明文只在首次安全展示/交付时可见 | 标准扩展模块；需 BIP-39 实现、密钥/验证器策略、宿主安全交付及恢复流程；不得日志记录 |
| EVM 钱包 | 仅纳入 MFA；推荐 SIWE/EIP-4361 challenge，绑定域、URI、用户、操作、chain ID、nonce、issued/expiry；校验签名与规范化地址及允许链；nonce 单次消费；钱包变更需现有因子或重新认证 | `auth-security-mfa-wallet` 可选；链清单 DB 配置，宿主提供地址归属策略/必要节点或合约钱包验证器 |

钱包协议已确认仅 EVM，但 SIWE/EIP-4361、允许的 chain ID、EOA 与合约钱包范围仍需定案。链切换不得改变既有凭证归属；增加链或换钱包应按变更流程重新证明，并使相关会话失效。

助记词是高价值长期知识凭证，12 词 BIP-39 的熵不应被描述为额外 MFA。默认不能明文存储。单纯哈希允许离线猜测风险评估须基于词数/熵；若应用需可恢复原助记词，则必须使用外部密钥加密并承担密钥泄漏风险。首选将应用作为预生成的密码型凭证接入，服务端只持有强验证器；遗失后按宿主身份恢复流程重新生成并吊销旧凭证和会话。助记词不能直接当作钱包 seed/private key。

### MFA 审计事件

扩展事件至少包括绑定开始/成功/失败、解绑、因子验证成功/失败、恢复码消费/轮换、恢复完成和 MFA 配置变化。事件只含不透明 user ID、因子类型、结果、时间、关联请求/挑战标识与风险元数据；不得包含秘密、验证码或完整 Token。安全审计目的地/保留策略由宿主提供。

## 9. OAuth2/OIDC 客户端登录

采用 Spring Security OAuth2 Client/OIDC Login 实现授权发起、回调、state/nonce 校验和 ID Token 验证；支持动态 `ClientRegistrationRepository` 从 DB 加载 provider 配置。优先 OIDC；只有必要时才对纯 OAuth2 provider 使用专门用户信息映射。Client Secret 不写入代码/YAML/仓库，密文由 `SecretProtector` 加密，根密钥来自外部安全设施。

```text
SPA -> GET /oauth2/authorization/{registrationId}
     -> Starter 产生并保存一次性 state、OIDC nonce 和注册配置版本
     -> 第三方 IdP 授权
IdP -> GET /login/oauth2/code/{registrationId}?code=...&state=...
     -> Spring Security 校验 state/nonce、交换授权码并验证 OIDC 身份
     -> FederatedIdentityMapper 根据稳定 (issuer, subject) 查找已关联用户
     -> 首登：仅按已验证邮箱关联既有本地用户；无匹配/冲突时拒绝自动关联
     -> 按本地用户安全状态和 MFA 策略完成后续认证
     -> 产生短时、一次性 OAuth login exchange code
SPA -> POST /api/auth/oauth2/exchange { code }
     <- 本系统 Access JWT + Refresh Token 响应体
```

禁止把 JWT 或 Refresh Token 放在 redirect URL、query 或 fragment。OAuth 回调后通过短时、随机、绑定 state/目标 SPA allowlist 且单次消费的 exchange code交付令牌。OAuth 状态/nonce 由共享短期存储保存，集群回调必须能读到发起节点状态。

邮箱关联策略：首次外部身份只有在可信 IdP 明确声明邮箱已验证且与现有本地邮箱唯一匹配时才允许按已确认方向进行关联；缺失/未验证/冲突必须拒绝并返回不泄露账号存在性的错误或交由宿主人工流程。关联后以 `(issuer, subject)` 为稳定身份键；后续邮箱变化不触发重新匹配或自动迁移。不得只靠相同邮箱解绑/覆盖已有外部身份。账号停用时拒绝登录且撤销/阻止会话。解绑由宿主要求本地强认证及其业务确认策略。

OAuth 登录共享本地用户 MFA 策略。IdP 的 MFA 声明只有在 issuer、claim 语义和 assurance 映射明确配置且验证可信时才能作为本地因子证明；默认不把 IdP 的登录视为本地 MFA 完成。第三方 Access/Refresh Token 默认不存、不转发、不作为本系统 JWT。

## 10. API DTO、错误与事件

- 登录/刷新/MFA/OAuth exchange 使用明确的 request/response DTO，由 Security Filter 转换和序列化；不将实体、内部异常或认证框架对象直接序列化。不为登录、登出、刷新增加 MVC Controller。
- 成功响应示例字段：`accessToken`、`tokenType`、`expiresIn`、`refreshToken`、`refreshExpiresIn`、`sessionId`、必要的 `mfaRequired`/`challengeId`。pending MFA 响应不得含完整权限 Token。
- 认证控制器异常与 Security Filter 异常分别处理：MVC `@ControllerAdvice` 和 Security `AuthenticationEntryPoint`/`AccessDeniedHandler` 都映射 RFC 9457 `ProblemDetail`，统一 `application/problem+json`，保留 bearer 401 的 `WWW-Authenticate`。
- 错误类别需区分未认证、MFA 未完成、Token 无效/过期、Refresh 重放、外部 IdP 失败、策略拒绝；对外错误不得泄漏邮箱是否存在、因子是否启用、密码/OTP 正误或第三方详细响应。
- 宿主可用 `AuthenticationProblemDetailMapper` 配置 title/type/业务扩展码；堆栈、密钥和凭证绝不放进 ProblemDetail。
- 认证事件至少包括登录成功/失败、登出、刷新成功、Token 重放、用户安全状态变化、MFA 变更、OAuth 映射成功/冲突。事件不含密码、密钥、OTP、恢复码、助记词或 token。
- 可观测性只提供不含标识或凭证的低基数事件/计数接口；不绑定 Micrometer 厂商实现，不以邮箱、用户 ID、token jti 等高基数字段作标签。

## 11. 安全责任分工

### Starter 提供

- JWT 签发/验证集成、Refresh 家族轮换与撤销 SPI、会话 DTO/服务。
- 登录、MFA pending 状态机、因子 SPI、OAuth2/OIDC Client 登录适配、端点映射和 ProblemDetail 默认处理。
- 条件化 Boot 自动配置、类型安全配置、公共事件和可选 JDBC/Redis、标准 MFA、WebAuthn、EVM 模块。

### 接入应用必须提供

- 用户 ID、邮箱规范化/唯一性、用户加载、主凭证校验、停用状态、业务授权与角色/租户映射。
- 生产密钥提供器、密钥轮换/KMS 权限、数据库/Redis 生命周期、凭证加密实现、备份与恢复。
- 邮件发送；钱包归属与智能合约钱包规则；助记词安全预生成、交付与丢失恢复流程。
- CORS 精确 allowlist、TLS/代理头信任、Cookie/CSRF 策略、OAuth 回调 URI/SPA redirect allowlist 和客户端密钥供给。
- OAuth 邮箱验证信任、账号冲突人工处理、身份解绑及业务级安全事件审计。
- 自定义 `SecurityFilterChain` 时显式接入认证过滤器/Resource Server/异常处理，不假设 Starter 覆盖宿主安全链。

## 12. 测试与验证计划

按行为选择最窄测试：无 Spring 领域逻辑用单元测试；属性校验/自动配置用 ApplicationContextRunner 或对应 Boot 测试支持；HTTP DTO/ProblemDetail 用 MVC slice；DB 并发与原子轮换用生产数据库引擎的容器集成测试；仅少量全应用启动和代表性 HTTP 测试。固定时钟、挑战值和随机源边界以确保可重复。

分阶段验收重点：

1. **工程/API 骨架**：多模块依赖方向、BOM、自动配置导入元数据、无默认兜底 SecurityFilterChain、配置绑定和校验、端点替换/禁用/冲突测试。
2. **Token/会话**：签名/issuer/audience/过期/多 kid；刷新原子轮换；并发仅一个胜者；旧 Token 重放撤销 family；登出/全登出/用户禁用和安全版本变化；存储不可用时 fail-closed 行为。
3. **MFA**：pending 状态不能访问受保护 API；一次性挑战；TOTP 确认绑定、时间步重放；WebAuthn origin/RP/challenge 校验；Email 用途绑定；恢复码单次消费；助记词敏感字段不出现在日志/DTO。
4. **OAuth**：动态注册绑定、授权 state/nonce 错误和重放、OIDC issuer 验证、邮箱已验证/未验证/冲突映射、停用用户、exchange code 单次消费和 redirect allowlist。
5. **存储/样例**：JDBC 迁移和真实数据库集成；Redis 原子脚本/并发验证；接入样例不含硬编码凭证，含自定义 `SecurityFilterChain` 集成方式。

发布前使用仓库 Maven Wrapper 执行 `./mvnw verify` 及技能要求的安全检查清单。此文档写入本身不代表以上测试或构建已执行。

## 13. 实施阶段

1. 创建父工程、BOM、core、autoconfigure、starter、sample；确定 API、类型安全配置、条件装配和端点契约。
2. 实现 JWT/JWKS 能力、刷新 Token 家族状态机、会话管理 SPI，再实现 JDBC/Redis 存储适配和并发测试。
3. 实现 MFA Core 与已确认的 TOTP、Email、恢复码、BIP-39；之后接入 WebAuthn 与 EVM 钱包可选模块。
4. 实现 OAuth2/OIDC Client、动态数据库注册、`FederatedIdentityMapper`、一次性 exchange 流程与策略测试。
5. 补齐样例、接入和运维文档、兼容性矩阵、自动配置测试及安全检查，按实际运行结果发布。

每阶段独立评审 API、威胁边界和测试结果；任何未经产品确认的账号关联、钱包协议或助记词行为不得被代码默认值固化为业务规则。

## 14. 参考依据

- 本机 `spring-boot-developer` 技能及其 Security fundamentals、MFA、OAuth2 login and SSO、JWT authentication、Configuration、Testing strategy、Hexagonal architecture、Maven、Spring Boot migration 指南。重点遵循 Boot 4/Security 7 API 版本、使用 Spring JWT Resource Server、服务端 staged MFA、类型安全配置、明确扩展边界和分层测试。
- sample 使用 React 19 / Vite 8：Maven `verify` 通过 Frontend Maven Plugin 执行 Node/npm 安装、lint、前端单测和打包；开发服务器通过 `/api` 同源代理到 Spring Boot，不额外启用 CORS；生产构建输出到 sample 静态资源目录。界面展示真实健康检查和实现阶段，不模拟尚未存在的登录成功。
- [Spring Boot System Requirements](https://docs.spring.io/spring-boot/system-requirements.html)
- [Spring Security OAuth2 Client Core](https://docs.spring.io/spring-security/reference/7.0/servlet/oauth2/client/core.html)
- [EIP-4361: Sign-In with Ethereum](https://eips.ethereum.org/EIPS/eip-4361)
- [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [OWASP HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)
