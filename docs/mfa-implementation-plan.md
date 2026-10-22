# MFA 实现方案

- 状态：分阶段实现中；当前支持已绑定 TOTP 与 Email 登录验证、用户绑定/解绑；未绑定用户使用密码登录；绑定和移除通过对应 MFA 因子自身的验证码确认
- 适用项目：`rose-security-spring-boot-starter`
- 技术基线：以仓库根 `pom.xml` 为准（当前 Java 25、Spring Boot 4.1.1、Spring Security 7）
- 关联文档：[Starter 总体设计](rose-security-starter-design.md)

本文记录 MFA 的最小可用架构、端点边界、状态流程，以及对 `skills/samples/mfa-demo` 的对照结论。它不把 demo 的实现约束当成产品需求。

## 1. 目标和边界

- MFA 默认关闭。关闭时现有登录、登出、全部登出和可选刷新流程不变。
- 启用后，配置/策略仅决定允许的因素；只有已绑定因素的用户需要完成登录 MFA，不支持强制用户绑定或验证。
- MFA 是现有 Spring Security 登录流程的一步。验证完成前不创建完整 `UserSession`，不签发完整权限 Token；成功后复用现有会话服务签发 Token。
- Starter 不管理用户、密码、邮箱生命周期或业务授权模型。主体标识沿用 Spring Security 的 `UserDetails#getUsername()`。
- 复用 Spring Security 原生过滤器、认证提供器、认证结果处理器及 WebAuthn 能力；不采用 Spring Security 7 内建 MFA 编排特性。
- 不提供限流功能、依赖、配置或扩展点。单次挑战自身的有效期、尝试上限、原子消费属于凭证安全要求。

## 2. 系统策略与用户设置

### 系统策略

系统策略包括总开关和允许的因素，不包含强制 MFA。MFA 默认关闭；配置文件提供静态允许因素，宿主可提供 `MfaPolicyProvider` Bean 整体替换默认策略，并为当前用户返回已绑定且可用于登录的因素。Bean 存在时不与默认策略逐字段合并；协议所需的静态配置（如 RP ID、Origin）仍由对应技术配置提供。Starter 不自带策略管理 HTTP API 或独立策略数据库。用户因素凭证和待验证事务仍走独立持久化边界，不存入配置文件。

Starter 默认不提供系统策略管理 HTTP API。管理员身份、授权、范围和策略审计都属于接入应用；接入应用可自行提供管理 API 并更新策略来源。

### 用户权限与 MFA 策略的边界

Starter 不定义角色、权限、用户组或租户模型，也不负责业务 API 授权。接入应用可通过 `MfaPolicyProvider` 返回当前用户已绑定且允许用于登录的 MFA 因素；Starter 不提供按角色或权限强制 MFA 的能力。角色/权限含义、用户分组和系统策略管理 API 均由宿主解释和维护。MFA 判断应使用已通过主认证并加载的本地用户身份；OAuth/OIDC 流程则在身份映射到本地用户后应用同一扩展点。不得仅因引入 Starter 就假定系统已有特定角色、权限 claim 或用户分组。

MFA 成功只表示本次登录完成了该用户已绑定的二次验证，不授予任何业务权限。普通 API 的访问控制仍由宿主的 Spring Security 授权规则决定。Starter 默认 JWT 不包含角色/权限 claim；接入应用若要在 Token 中携带授权数据，应自行定义并配置其签发与 Resource Server 映射。

### 用户设置

用户可通过 `/api/me/mfa` 查看和管理已绑定凭证。是否有可用于登录的 MFA 因素必须以凭证存储为准，不能只依赖用户可写的布尔字段；用户没有已绑定因素时仍可使用密码登录。

用户可以移除最后一个 MFA 因素。绑定和移除须证明对该因素的控制权：TOTP 提交当前有效验证码；Email 先向当前登录邮箱发送短时验证码，再调用该因素的验证端点。用户移除最后因素后，后续登录使用密码完成。MFA 变更不使现有会话自动退出；如需策略变化即时影响请求，接入方仍须在授权阶段查询当前状态。

## 3. API 端点

默认认证基础路径 `/api/auth`，当前用户 MFA 管理路径 `/api/me/mfa`。认证路由复用 `auth.security.endpoints.base-path`；MFA 管理根路径通过 `auth.security.endpoints.me-mfa` 单独配置，因为它不在 `/api/auth` 下。应用可调整路径；冲突时由应用配置和授权规则一并调整。

| 方法 | 默认路径 | 访问条件 | 用途 |
|---|---|---|---|
| `GET` | `/api/auth/mfa/options` | 公开 | 返回系统全局启用且已配置实现的登录 MFA 方式；不表示某个用户已绑定该方式 |
| `POST` | `/api/auth/mfa/challenge` | 有效的待完成 MFA 事务 | 按因素创建挑战或触发必要动作，例如发送 Email OTP |
| `POST` | `/api/auth/mfa/verify` | 有效的待完成 MFA 事务 | 验证证明；成功后完成登录并签发 Token |
| `GET` | `/api/me/mfa` | 完整认证用户 | 查询当前用户已绑定方式状态 |
| `PUT` | `/api/me/mfa` | 完整认证用户且主认证时间在有效窗口内；关闭或修改已启用的 MFA 时还要求近期 MFA | 更新用户可管理的偏好 |
| `POST` | `/api/me/mfa/{method}` | 完整认证用户 | 开始绑定并返回因子所需的设置数据/挑战；Email 会向当前邮箱发验证码 |
| `POST` | `/api/me/mfa/{method}/verify` | 完整认证用户发起的有效绑定事务 | 确认挑战并完成绑定 |
| `DELETE` | `/api/me/mfa/{method}/{credentialId}` | 完整认证用户 | 开始解绑挑战；由对应 MFA 验证端点确认后才解绑 |
| `POST` | `/api/me/mfa/recovery-codes` | 完整认证用户且近期完成 MFA | 生成/轮换恢复码；仅本次响应展示明文 |

`{method}` 的登录 MFA 标识由实际支持的实现注册，例如 `totp`、`webauthn`、`email`、`wallet`、`mnemonic`。恢复码是备用登录凭证，不宜伪装成可绑定的设备因素；其校验可通过登录 MFA 的 verify 流程提交，并作为 `options` 中单独的备用方式返回。BIP-39 助记词是可绑定、可验证、可解绑的常规 MFA 方式，不是主登录凭证，也不承担账号恢复流程。

### 请求与响应约定

- 登录请求沿用现有认证端点。需要 MFA 时，认证成功处理器返回 `mfaRequired`、不透明短时事务标识和该用户已绑定且策略允许的方法，不返回 Access/Refresh Token。全局 `/options` 是能力目录，不代表该用户具备对应凭证。首次可选绑定若当前尚无因素，用户需先完成近期主认证；绑定已有因素后的变更要求近期完成 MFA。
- challenge 请求携带事务标识和方法；登录挑战只接受该用户已绑定且允许的因素。verify 请求携带事务标识、方法和证明。
- 待验证事务标识不是 Access Token，只能调用该事务允许的 MFA challenge/verify 操作；不接受其访问业务 API。
- `GET /api/auth/mfa/options` 返回全局可用的登录方式，不泄露用户绑定状态或凭证信息；它可能列出当前用户未绑定的方式。`GET /api/me/mfa` 才返回当前用户的绑定摘要。
- 使用最少的 DTO，不暴露实体、存储对象或 Spring Security 内部对象。错误响应由接入应用现有 Spring Security 处理器决定，不强制 `ProblemDetail`。
- WebAuthn 浏览器 ceremony 若必须通过 Spring Security 原生端点完成，可保留其框架路径；不要为了统一 URL 而复制一套 WebAuthn 协议实现。

系统策略读取/修改端点不由 Starter 默认提供。用户 API 与管理 API 分离：`/api/me` 仅管理当前用户，系统策略管理由宿主应用承担。

### 用户尚未绑定 MFA 因素

用户尚未绑定任何因素时，密码登录直接创建普通会话并签发 Token；不创建首次绑定事务。绑定始终由已登录用户通过 `/api/me/mfa/{method}` 发起，完成绑定后后续登录才要求该因素验证。

## 4. 状态和主流程

### 登录 MFA

1. 现有登录过滤器通过 `AuthenticationManager` 验证主凭证。
2. 宿主提供的策略来源根据本地用户身份及其宿主定义的属性（可包括 `UserDetails#getAuthorities()`）判断本次登录是否需要 MFA，以及允许使用哪些已绑定因素；Starter 不解析角色名或权限层级。
3. 不需要 MFA 时，照常创建 `UserSession` 并签发 Token。
4. 需要 MFA 时，创建短时待验证事务并返回 pending 状态；此时不创建完整会话、不签发 Token。
5. 客户端按需请求 challenge，再提交证明至 verify。
6. 服务端校验事务主体、用途、因素、过期时间及一次性状态，并原子消费挑战/一次性凭证。
7. 本地登录成功后通过现有会话服务创建会话并签发 Token；OAuth/OIDC 登录成功后按下节所述策略完成 MFA，再产生一次性兑换码，由兑换端点创建会话并签发本系统 Token。记录实际认证方法和认证时间（如 `amr`/`auth_time`）。失败、过期、重放或存储不可用时均不得签发 Token。

待验证事务需受限于单次登录和允许的因素，设置短有效期及有限验证尝试；过期、成功、取消后均不可复用。并发重复提交必须只有一个成功。

在完成 MFA 并签发 Token 或 OAuth exchange code 前，须确认本地用户仍有效，并确认事务中的因素仍绑定且允许用于登录。若用户被禁用或因素已不再允许，应拒绝完成并要求重新登录。Starter 不解释权限，当前状态与因素策略由宿主提供。

OAuth exchange code 兑换时也须重新确认本地用户仍可登录；若账号已禁用或身份关联已撤销，则拒绝兑换并要求重新登录。通过检查后再按现行会话/安全版本规则签发会话。

### OAuth2/OIDC 登录 MFA

OAuth2/OIDC 回调完成 state/nonce 校验、身份验证和本地用户映射后，若用户已有可用的本地 MFA 因素，则创建绑定到该用户及本次 OAuth 登录的短时 `LOGIN` 事务；没有已绑定因素时直接签发短时一次性 OAuth exchange code，由 OAuth exchange 端点创建本地会话并返回本系统 Token。默认不把 IdP 返回的 MFA 声明视为本地 MFA 已完成；只有宿主显式配置并信任相应 issuer、声明语义和 assurance 映射时才可接受。账号映射/停用策略仍由总体设计和接入应用负责。

### 因子绑定与解绑

绑定是两阶段流程：开始绑定 -> pending 凭证/挑战 -> 用户证明 possession -> 持久化为 active。只有确认成功且当前允许的已绑定因素才能用于登录。解绑也采用挑战/确认两阶段流程，必须由目标因子本身验证：如解绑 Email，Starter 先向当前登录邮箱发验证码，客户端提交 challenge token 与验证码，验证成功才关闭 Email MFA。Email 的一次性挑战按用户、用途和有效期绑定，服务端只存基于不透明随机挑战 token 计算的 HMAC proof。宿主 Store 必须原子完成 challenge 消费和 Email MFA 状态变更，并记录失败次数；不能拆成先消费、后开关 MFA 的两个非原子操作。用户可以移除最后一个因素；下次登录回到密码登录。MFA 凭证变更不撤销用户会话或强制退出；JWT 的 `amr` 仍表示签发时实际完成的认证因素。接入应用若要求策略变化后即时影响当前请求，需在授权时检查当前 MFA 状态；无状态 Access Token 的签名声明不会被 Starter 原地改写。Starter 不替宿主决定业务范围或审计语义。

恢复码生成/轮换时旧码整批立即失效，新码只显示一次。全部遗失后的身份恢复属于接入应用的账号恢复流程，Starter 不替代业务身份核验。

### 最小领域状态与存储操作

不要求实现必须创建同名 Java 类；以下是持久化必须表达的概念和原子行为：

- **策略**：表达系统 MFA 开关、允许因素和当前用户已绑定且可用于登录的因素；不包含要求 MFA 或按权限强制的策略。
- **凭证**：属于一个用户名和因素，至少能区分待确认、有效、撤销状态，并记录方式需要的验证材料。助记词凭证属于 `LOGIN_MFA`，可在主认证成功后的待验证 MFA 事务中验证；不得用于主登录或账号恢复。
- **事务**：登录 MFA 事务绑定用户名、已绑定且允许的因素、到期时间及消费状态；绑定/移除 challenge 另按管理用途校验，不能跨用途使用。
- **原子操作**：确认绑定、消费 challenge、消费恢复码、轮换恢复码以及移除凭证时维护状态一致性，必须在并发下保持一致。移除最后因素后用户回到密码登录。取消/过期事务不能再完成绑定或认证。若宿主将策略、偏好和凭证分库存储，须由宿主提供等效的一致性保障，不能依赖先读后写的非原子检查。

这些是对存储实现的行为约束，不要求按每条概念新增一个接口、服务或 DTO。

### 会话与二次认证边界

本方案首期覆盖登录 MFA 与因子自身的绑定/解绑验证，不提供通用业务 step-up API。若接入应用还要保护其他高风险业务操作，应另行定义策略和状态更新机制。示例项目的五分钟 Session 标记不能直接移植到无状态 JWT。

## 5. 因素规则

| 因素 | 绑定和验证要求 | 存储/接入边界 |
|---|---|---|
| TOTP | CSPRNG 生成密钥；展示 `otpauth` 数据；绑定前验证一次有效 OTP；窄时间窗并拒绝已接受时间步重放 | 密钥需加密存储；加密密钥由宿主安全提供 |
| WebAuthn | 注册/断言挑战绑定用户、操作、RP ID、Origin 和期限；校验 challenge、RP ID hash、签名、credential ID 与用户验证要求；使用后失效 | 优先复用 Spring Security WebAuthn。RP ID 和 Origin 可配置；无状态部署的挑战/凭证存储需可共享和持久化 |
| Email | OTP 绑定用户、用途和挑战；用于登录、绑定确认及解绑确认；短时有效、一次性消费，错误达到挑战自身上限后作废 | 发信由接入应用提供；核心不绑定邮件供应商。接收地址沿用当前已认证主体的 email username；Starter 不自行查询用户表 |
| 恢复码 | 高熵随机值，只展示一次；每码一次性，轮换后旧码作废 | 只保存安全验证值，支持原子消费；丢失恢复由宿主负责 |
| EVM 钱包 | 参考 demo 使用 EIP-191 `personal_sign`：挑战不可预测、绑定用户和操作、不可重放；服务端恢复签名地址并与绑定地址比较 | 登录挑战绑定待验证 MFA 事务，绑定挑战绑定当前用户会话。部署域名、URI、chain ID/allowlist 必须由宿主配置并纳入签名消息；不复制 demo 的 localhost/chain ID 1。合约钱包支持范围仍需定案 |
| BIP-39 助记词 | 英文词表 12 词；预生成并由用户绑定为 MFA 凭证；仅作为主认证后的 MFA 证明，不用于主登录或账号恢复 | 不明文存储/记录，不派生钱包私钥；持久化前规范化并以带盐的抗暴力口令哈希保存验证值，验证采用常量时间比较；绑定、替换和解绑须验证目标助记词凭证。预生成与安全交付由接入应用负责 |

任何日志、异常、事件和观测都不得包含 TOTP 秘钥、OTP、恢复码、助记词、钱包签名、完整挑战秘密或 Token。错误对外避免泄露用户是否存在、绑定情况或证明正确性。

账号恢复不是助记词 MFA 的用途：Starter 不提供账号恢复 HTTP 端点，也不依据助记词自行重置账号或签发登录 Token。助记词证明仅可完成主认证后的 MFA 验证，不能独立登录或绕过 MFA 流程。

## 6. 自动配置和扩展边界

- 默认 MFA 策略实现读取类型安全配置文件属性；宿主提供 `MfaPolicyProvider` Bean 时，自动配置回退并使用宿主实现，不与配置文件驱动策略逐字段合并。配置和 Bean 都缺省时 MFA 默认关闭。策略允许启用时，所需凭证/挑战存储和因素实现必须已具备。
- 策略启用了但没有对应因素实现或必需依赖时，视为配置错误并拒绝启动或拒绝该认证流程，不能从 `options` 中静默隐藏后继续接受不完整策略。
- Starter 不无条件接管已有 `SecurityFilterChain`。登录 MFA 过滤器应按项目现有 `AuthSecurityConfigurer` 集成方式配置；应用自定义链时自行添加配置器并明确允许/保护端点。
- 优先保留三个实际边界：策略读取、MFA 数据存储、因子实现。实现时先检查已有类/扩展点是否可承载，确认有调用者后再新增公共类型。
- 配置文件驱动的静态策略是默认实现；宿主 `MfaPolicyProvider` Bean 可完整替换它并提供数据库或其他动态策略。宿主负责动态策略的缓存失效和集群一致性；不把数据库依赖放进核心 Starter。
- 凭证和待验证事务存储必须支持必要的原子写入/消费。可复用现有 JDBC/Redis 自动装配约定；不为尚未确认的存储方案预造模块。
- 邮件发送、钱包/链规则、助记词安全交付及账号恢复流程由接入方提供或配置。
- 沿用 Spring Security 的认证成功/失败处理器、异常处理器及原生认证事件；不新增 Starter 自有事件发布机制。

以下为静态部署参数示例。用户允许方式和绑定状态可由宿主 `MfaPolicyProvider` 从数据库读取；WebAuthn RP ID 与 allowed origins 属于部署级配置，当前通过 `auth.security.mfa.webauthn-rp-id` 和 `webauthn-allowed-origins` 提供：

```yaml
auth:
  security:
    endpoints:
      base-path: /api/auth
      me-mfa: /api/me/mfa
      mfa-verify: /mfa/verify
    mfa:
      enabled: false
      methods: []
      transaction-ttl: 5m
      maximum-attempts: 5
      totp-issuer: Example Application
```

当前代码已绑定这些静态默认策略字段并提供可替换的 `MfaPolicyProvider`。`MfaLoginTransactionStore` 定义按 Token 摘要存储、原子消费及失败尝试计数；只有接入方提供 Store Bean 才会装配事务服务与 `/api/auth/mfa/verify` 过滤器。登录成功处理器按 `MfaPolicyProvider` 判断；需要 MFA 时返回 `202 Accepted`、不透明短期事务 Token、允许方式和到期时间，不创建会话或完整 JWT。验证使用 `MfaFactorAuthenticationToken` 调用因素 `AuthenticationProvider`；因子认证成功并原子消费事务后，复用既有 `UserSessionService` 签发会话和 Token。失败处理沿用接入方的 `AuthenticationFailureHandler`。

当前代码包含 TOTP RFC 6238、Email OTP 和 WebAuthn MFA 登录/绑定/解绑流程，并沿用 Spring `AuthenticationProvider` 与管理过滤器。管理路径默认为 `GET /api/me/mfa`；TOTP 使用 `POST /totp` 开始、`POST /totp/verify` 确认、`DELETE /totp` 提交当前验证码后移除；Email 使用 `POST /email` 发起绑定、`POST /email/verify` 确认，`DELETE /email` 发起移除验证码、`POST /email/remove/verify` 确认移除。WebAuthn 使用 `POST /webauthn/register/options` 与 `/webauthn/register` 绑定；`POST /webauthn/remove/options` 与 `/webauthn/remove` 先验证该用户的通行密钥再移除；登录阶段由 `POST /api/auth/mfa/webauthn/options` 使用待完成登录事务生成 assertion options，再由通用 `mfa-verify` 校验 assertion。WebAuthn 协议与签名校验复用 Spring Security 7.1 WebAuthn API，RP ID 和 Origin 来自配置。WebAuthn 挑战通过 `WebAuthnMfaChallengeStore` 按用户名、操作、期限与（登录挑战的）事务 Token 摘要保存，Store 必须在字段匹配时原子消费。Email 挑战通过 `EmailMfaStore` 保存 HMAC proof，邮件发送由 `MfaEmailSender` 提供。密码登录后，仅当用户已有已绑定且允许的方式时才创建短时 MFA 事务；未绑定因素的用户直接获得普通会话和 Token。宿主提供相应凭证/挑战持久化、邮件发送和短期 `MfaLoginTransactionStore`；TOTP Store 必须加密 pending/active secret 并原子确认绑定和消费时间步。绑定或移除不会撤销会话或强制退出。钱包、恢复码、BIP-39 助记词仍未实现。`mfa-verify`、WebAuthn 登录 options 与用户管理路径需和宿主 `SecurityFilterChain` 授权规则同步。

钱包、恢复码、BIP-39 助记词尚未实现。默认策略只将用户已绑定且允许的方式列为登录因素；自定义 `MfaPolicyProvider` 也必须返回用户实际可用的已绑定方式。用户存在已绑定且允许的因素但缺少事务 Store 时，登录失败关闭且不签发 Token；缺少 Store 时相应验证过滤器不注册。登录、verify 和 WebAuthn options 路径需按其用途由宿主 `SecurityFilterChain` 明确允许匿名访问，用户 MFA 管理路径必须认证。该 YAML 不含用户动态状态。若策略来自数据库，由宿主 Bean 提供；缓存刷新和集群一致性由应用负责。WebAuthn 凭证和 challenge 的 JDBC/Redis 适配目前不包含在 starter 中，应用须提供可共享且支持原子消费的实现；内存仓储仅适用于本地演示。

## 7. 与 `skills/samples/mfa-demo` 对照

比较对象：本机工作区中的 `skills/samples/mfa-demo`（Spring Boot 4.1.1、Spring Security 7、Java 25 的本地演示）。示例有可复用的交互验证价值，但不是 Starter 目标架构的直接模板。

| 主题 | mfa-demo 实际做法 | Starter 方案的调整 |
|---|---|---|
| 认证状态 | Form Login + HttpSession，部分认证保存在 Spring Security `Authentication`、authority 和 session attribute | Starter 是 JWT/`UserSession`；MFA pending 状态需短时服务端事务，成功后才调用会话服务签发 Token，不能依赖 servlet session 状态 |
| Spring Security MFA | 示例使用 `@EnableMultiFactorAuthentication` | 用户已明确不采用 Security 7 MFA 特性；只复用过滤器链、`AuthenticationProvider`、WebAuthn 等底层原生扩展 |
| MFA HTTP 实现 | `MfaController` 使用 MVC Controller；challenge/verify 由控制器处理 | 登录、登出、刷新已有约定为过滤器流程。登录 MFA challenge/verify 应纳入 Security Filter 适配，不平行新增 Controller 认证通道；`/api/me` 因子管理若需要 HTTP 边界，按项目现有方式实现 |
| 登录端点 | `/login` Form Login 与 WebAuthn passkey 主认证 | Starter 主登录沿用现有邮箱/密码认证；WebAuthn MFA 不能照搬成另一个主登录方案 |
| challenge | 已有 `/api/auth/mfa/challenge`、`/verify`，按因子创建 challenge 或验证证明 | 保留简短的两段式设计。增加系统可用因子只读查询 `/api/auth/mfa/options`；采用 `/api/me/mfa` 管理用户设置/因素 |
| 因子管理 | `/api/mfa/totp/enroll`、`/confirm` 等逐因子路径；删除按 factor type | 统一短路径 `/api/me/mfa/{method}` 和 `/verify`，解绑需 credentialId 以支持多凭证；恢复码单独轮换端点 |
| 配置 | 因子、允许状态与用户偏好以 demo 代码写死；没有通用系统策略管理/查询 API | 系统策略与用户设置分离；策略来源可配置或数据库化。Starter 不默认提供管理员策略管理 API |
| 存储 | `ConcurrentHashMap`、内存用户和 Spring Security WebAuthn 内存 repository，重启丢失 | 生产能力必须用共享持久化存储，并支持 challenge/恢复码原子消费；具体 JDBC/Redis 适配按仓库模块边界评估 |
| Email | 验证码直接打印控制台 | 只能作为本地 demo 行为，Starter 必须使用宿主发信实现；绝不能打印验证码 |
| TOTP | 展示 secret 并确认，演示逻辑拒绝重放时间步 | 可复用流程要点；Starter 还需加密静态秘密、绑定用户/操作/期限并处理并发验证 |
| WebAuthn | 独立框架路径和内存凭证库；passkey 可作主认证，后续再加第二因子 | 复用 Spring Security 的 WebAuthn 协议实现与 RP/Origin 校验，但凭证用途必须是 MFA 因素；无状态 API 的 challenge 存储与完整权限 Token 流程需适配 |
| 钱包 | web3j EIP-191 `personal_sign`；demo 挑战绑定用户/session、含随机 nonce 和过期时间，但域名/URI/Chain ID 固定为 localhost/1 | 参考签名恢复与地址比较及一次性挑战；域名/URI/chain ID 改为部署配置，并验证完整消息字段；不将 demo 固定值当生产协议 |
| 助记词 | 示例用 web3j BIP-39 生成 12 词，并将 SHA-256 摘要用于可重复 MFA 验证 | 采用英文 BIP-39 12 词作为可绑定的常规 MFA 凭证；凭证预先生成，不能用于主登录或账号恢复。不得照搬快速 SHA-256 验证值存储，改用带盐的抗暴力口令哈希 |
| 恢复码 | demo 不提供恢复码 | Starter 方案需要恢复码生成、一次性消费、轮换和耗尽后的宿主恢复责任 |
| step-up | demo 在 session 中记录最近 5 分钟 MFA 并保护安全操作 | 不是首期登录 MFA 的自动组成部分；JWT 无状态部署必须先决定认证状态续签/共享查询，不能直接复制 session 属性 |
| 错误格式 | demo 自带 `ProblemDetail` 安全处理器 | Starter 不固定 `ProblemDetail`；沿用宿主 Spring Security 异常处理扩展点 |

### 对照后的方案修订

1. 明确首期目标为登录 MFA 与用户凭证管理；绑定和移除由目标因素自身的验证完成，通用业务 step-up 不属于首期。
2. 补齐 `/api/auth/mfa/options`，供登录界面展示当前可用方式；它不替代用户的绑定状态查询。
3. 登录 challenge/verify 放入既有 Security Filter 流程，不复制 demo 的 MVC 登录控制器。
4. 因子管理归 `/api/me/mfa`；系统策略管理端点归宿主，不由 Starter 默认暴露。
5. 保留 demo 有效的协议流程参考，但淘汰其内存存储、控制台验证码、硬编码钱包域/网络、session 认证状态及助记词凭证的 SHA-256 存储方式。

## 8. 实施顺序与验收

1. 先实现关闭时无行为变化、策略判定、pending MFA 事务和过滤器接入；证明 MFA 未完成不能访问受保护 API，且不会产生完整会话/Token。
2. 实现持久化边界和原子 challenge 消费，再实现 TOTP 与恢复码的绑定、验证、轮换。
3. [x] 接入 Email（宿主发信）和 WebAuthn（复用 Spring Security 能力）。
4. 钱包协议/网络确认后接入钱包方式；助记词作为常规 MFA 方式接入，采用预生成的英文 BIP-39 12 词和专用验证器。
5. 提供自定义 SecurityFilterChain、策略来源替换、存储替换和用户接口调用示例。

验收应覆盖：默认关闭及自动配置条件；MFA pending 不得获完整权限；本地和 OAuth 登录在已有因素和无已绑定因素时的路径；策略或用户状态在 pending 期间变化后不得沿用失效授权；挑战成功、错误、过期、重放和并发重复提交；绑定确认后才激活；移除最后一个因素后允许密码登录；恢复码一次性消费/轮换；会话撤销与 Access Token TTL/即时校验语义；因子依赖缺失时的启动/请求行为；自定义 Bean 替换；敏感信息不出现在响应、日志和事件。

## 9. 尚待确认的实现决策

1. EVM 钱包采用的签名标准、允许网络/chain ID、EOA 与合约钱包范围。
2. 用户因素凭证及待验证事务的首版持久化方式需与 MFA 策略配置来源区分决定；配置文件默认读取系统策略，不自动等同于可变用户凭证/挑战存储。存储方案优先复用宿主 Bean，只有明确需要时再增加 JDBC/Redis 适配。
3. 用户关闭个人 MFA、移除最后一个因素已确认允许；MFA 管理操作优先接受配置窗口内的近期 TOTP 认证，否则通过主 `AuthenticationManager` 校验账户密码。MFA 不支持强制模式；用户移除最后一个因素后可直接密码登录。
4. 因子绑定和移除由目标因子自己的证明确认：TOTP 使用验证码，Email 使用邮件验证码。其他因子接入时也应提供相应的 challenge/verify 流程。
5. 助记词凭证轮换/重新绑定的用户体验和验证窗口；其作为常规 MFA 因子参与绑定、验证、解绑，不承担账号恢复。

