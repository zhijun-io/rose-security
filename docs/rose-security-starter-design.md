# Rose Security Spring Boot Starter 设计方案

- 状态：设计基线；本地认证、JWT、Token 会话、JDBC/Redis 会话适配及 TOTP MFA 完整基础流程已实现；其他 MFA 因子与 OAuth2/OIDC 待实现
- 项目：`rose-security-spring-boot-starter`
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
| MFA 类型 | TOTP、WebAuthn、Email、恢复码、BIP-39 助记词、EVM 钱包 | 已确认类型；钱包协议待定。助记词是可绑定的常规 MFA 方式，只用于主认证后的二次验证，不可单独主登录或账号恢复 |
| OAuth | Spring Security OAuth2 Client/OIDC Client；OAuth 注册信息可由数据库运行时提供 | 已确认 |
| MFA/OAuth 配置 | MFA 支持配置文件驱动的静态默认策略，也支持宿主 `MfaPolicyProvider` Bean 整体替换；OAuth Client Registration 使用运行时配置源 | 已确认；用户凭证和一次性挑战由独立存储 Bean/适配持久化，不写入配置文件 |
| Token | 短期 Access JWT + 长期 Refresh Token；Refresh Token 通过响应体传输；提供 JDBC/Redis 可选适配 | 已确认 |
| JWT 与 Refresh 模式 | 可配置；关闭时只签发 Access Token，但仍建立与 Access Token 同寿命的服务端会话 | 当前实现要求 |
| 认证端点实现 | 登录、登出、刷新经 Spring Security Filter Chain，不新增 MVC Controller | 已确认 |
| API 错误 | 由接入应用选择格式；Starter 默认只设置通用 HTTP 状态，不固定响应体结构 | 已确认 |
| 项目模块名 | 父工程 `rose-security-spring-boot-starter-parent`；接入用依赖模块 `rose-security-spring-boot-starter` | 已确认。两者需区分以避免 Maven GAV 重复 |

### 推荐默认值（可配置，不是不可变协议承诺）

- Access Token：RS256、10 分钟；Refresh Token：随机不透明值、14 天滑动或固定到期时间由产品配置选择。JWT 中包含 `iss`、`aud`、`sub`、`jti`、`iat`、`nbf`、`exp` 和认证方法/时间声明，不内置角色或租户含义。
- Refresh Token 只存储哈希，放在服务端会话家族记录中，使用时原子轮换；检测到旧 Token 再次使用则撤销整个家族。
- 待完成 MFA 状态采用服务端短时、不透明、一次性挑战；它不能作为 API Access Token 使用。
- Starter 不规定浏览器存储方式。当前演示将 Token 保存在标签页级 `sessionStorage`，以支持页面重载后恢复；关闭标签页后清除，并在总览显示完整 Refresh Token。该示例仅用于演示，不能用于生产；`sessionStorage` 和页面展示的 Token 均可被同源脚本读取，生产应用需评估 XSS 风险，并按威胁模型选择内存加重新认证或 HttpOnly Cookie 等方案。
- OAuth 首次登录不自动创建业务用户。只有按配置的邮箱映射策略成功匹配已有用户后，才创建 `(issuer, subject)` 外部身份关联。
- 助记词采用 BIP-39 英文词表、12 词，由应用侧预先生成后交给用户绑定为 MFA 凭证；只用于主认证后的二次验证，不可单独主登录或账号恢复，也不用作 TOTP 秘钥或钱包私钥。Starter 不负责账号恢复业务。

## 3. 待决定事项

这些事项不阻止先实现模块骨架和安全接口，但在发布可互操作的功能前必须明确。

| 事项 | 推荐选项 | 影响 / 需要确认 |
|---|---|---|
| 发布 `groupId` 与版本策略 | 使用 `io.zhijun`；发布前确认该命名空间归属及发布仓库要求；语义化版本 | 当前 Maven 坐标已统一；只有确认命名空间可由发布方使用后再发布 |
| JWT 密钥部署 | 默认 RS256 实现使用宿主 `JWKSource` 或配置的 PEM；公开 JWKS 和多 `kid` 支持 | 不可导出的 KMS/HSM 私钥需由宿主替换 `JwtTokenIssuer` 与 `JwtDecoder`；需确定部署环境和签名权限边界 |
| `iss`、`aud` 和 Token TTL | 每环境显式设置；Access 短期、Refresh 中长期 | API 消费方必须校验同一发行者和受众；配置缺失时生产启动失败 |
| Refresh 生命周期 | 推荐绝对期限 + 可选滑动期限、家族记录和单次轮换 | 确认是否采用滑动续期、会话最大寿命和并发设备政策 |
| MFA 策略 | 默认关闭；启用后用户可选择并绑定允许的方式；仅对已绑定因素的用户执行登录二次验证 | 未绑定因素或已移除全部因素的用户仍可使用密码登录；不提供强制 MFA 或首次绑定登录事务 |
| WebAuthn | 管理员配置 RP ID 和精确 Origin allowlist | RP ID 必须是部署域名的有效域；跨域、反向代理、开发域名需单独配置 |
| 钱包认证 | 仅 EVM；建议 SIWE / EIP-4361，并明确链 ID allowlist | 链 ID、钱包签名兼容范围、地址规范化、是否接受合约钱包/智能账户需确认 |
| BIP-39 助记词 MFA 凭证 | 12 词英文，预生成；绑定后用于主认证后的 MFA 验证 | 由应用安全生成并交付；以带盐的抗暴力口令哈希保存验证值；不能作为钱包 seed/private key 或账号恢复凭证 |
| OAuth 邮箱关联 | 仅在 IdP 明确返回 `email_verified=true` 时自动匹配；持久化 `(iss,sub)`；无已验证邮箱不自动关联 | 确认是否允许人工账号关联、邮箱冲突人工处理、IdP 更换/账号解绑规则；不得仅以当前邮箱重关联既有 `(iss,sub)` |
| 令牌返回与 SPA | Refresh Token 通过响应体返回；当前演示用标签页级 `sessionStorage` 保存以支持重载恢复，并显示完整 Refresh Token；OAuth 回调使用一次性兑换码再由前端 POST 兑换 | 明文展示和浏览器存储仅为演示取舍，不可用于生产；兑换码 TTL 与允许的 SPA 回调 URL allowlist 待确认 |
| 会话后端 | 生产环境至少一个共享、支持原子比较与更新的 JDBC 或 Redis 后端 | 确认数据库种类、Redis 可用性目标；多实例即时撤销需要共享查询能力 |
| API 错误约定 | 接入应用按自身 API 约定配置 Spring Security 处理器；Starter 认证过滤器默认不返回固定错误响应体 | 错误码命名空间、字段扩展与国际化由接入应用确定 |
| 配置管理 API | Starter 提供管理服务/接口，HTTP 管理端点可选或由宿主暴露 | 配置修改的管理员授权和变更审计属于宿主应用；需确定管理 API 是否纳入首版 |

## 4. 模块结构

当前工程只保留已存在且边界明确的 Maven 模块。不要为尚未实现的认证方式预建空模块；先在相应功能实现时验证依赖和发布边界，再决定是否拆分。

```text
rose-security-spring-boot-starter/          # 仓库目录
├── pom.xml                                 # 父工程（artifactId: rose-security-spring-boot-starter-parent）
├── rose-security-spring-boot-starter-bom/  # 消费方版本对齐 BOM
├── rose-security-spring-boot-core/         # 认证、Token、会话与扩展 API；不绑定存储/厂商
├── rose-security-spring-boot-autoconfigure/ # Boot 自动配置、属性、条件装配、HTTP 边界
├── rose-security-spring-boot-jdbc/         # 可选 JDBC 会话存储
├── rose-security-spring-boot-redis/        # 可选 Redis 会话存储
├── rose-security-spring-boot-starter/      # 便捷依赖，组合核心自动配置和默认必需依赖
└── rose-security-sample/                   # 接入示例应用和端到端用法
```

按真实依赖边界拆分可选模块：JDBC 和 Redis 分别作为存储适配模块；OAuth2/OIDC Client 依赖与核心隔离时再拆客户端模块；MFA 先作为一个完整功能边界实现，只有某因子引入明显独立的大型依赖或需要独立发布时，才将该因子拆出。TOTP、Email、恢复码和 BIP-39 不按类型机械地各建一个模块。

### 依赖边界

- `core` 仅包含 Java/Spring Security 领域契约，不能依赖 JDBC、Redis、邮件、钱包或特定 IdP。
- `autoconfigure` 提供 Boot 4 自动配置元数据；使用 `@AutoConfiguration`、经过验证的 `@ConfigurationProperties`、`@ConditionalOnClass`、`@ConditionalOnProperty`、`@ConditionalOnMissingBean`。依赖缺少时应清楚失败或关闭能力，不能静默降级为不安全模式。
- `starter` 只组合默认核心依赖，不强制引入 JDBC、Redis、WebAuthn 或 EVM 库。消费者按需追加集成模块。
- 本地登录直接使用宿主提供的 Spring Security `UserDetailsService`、`AuthenticationManager` / `AuthenticationProvider` 和 `PasswordEncoder`；Starter 优先采用宿主提供的唯一或 `@Primary` `AuthenticationManager` Bean，没有该 Bean 时才从 `AuthenticationConfiguration` 获取框架全局管理器。不创建 `DaoAuthenticationProvider` 或默认密码编码器。JWT 的 `sub` 使用 `UserDetails.getUsername()`，当前约定为邮箱。
- 可选存储适配实现公共 Repository/Store 接口；同一部署的会话状态只选一个权威后端，不做无事务双写。
- 自动配置不注册一个无条件兜底、捕获全部流量的 `SecurityFilterChain`。默认仅提供可组合的过滤器、认证器及安全配置组件；如提供默认链，必须由显式属性启用，且以 `@ConditionalOnMissingBean(SecurityFilterChain.class)` 让宿主完全接管。
- 自定义安全链的应用显式集成 JWT Resource Server、认证端点 matcher 和所需的认证/拒绝访问处理器；Boot 4/Security 7 使用 lambda DSL。Bearer API 可以无状态并关闭 CSRF；若接受 Cookie，则必须保留 CSRF 防护。
- 登录使用 Spring Security `AuthenticationFilter`、JSON `AuthenticationConverter`、`AuthenticationManager` 和 JSON 成功/失败处理器；登出使用链内建 `LogoutFilter`，接入 family 撤销 `LogoutHandler`；刷新使用只匹配刷新路径的专用认证过滤器/`AuthenticationManager`。这些流程不经过 MVC Controller。OAuth 登录回调由 Spring Security OAuth2 Login 过滤器处理；MFA 验证按同样的链内 filter adapter 暴露。

## 5. 核心扩展接口

建议 API 包围绕端口定义，HTTP DTO 与存储模型分别放在适配模块，不暴露实体。

| 接口建议 | 宿主/适配职责 |
|---|---|
| Spring Security `UserDetailsService` | 宿主按邮箱（username）加载本地用户，并配置 `AuthenticationManager` / `AuthenticationProvider` 与 `PasswordEncoder`；Starter 优先采用宿主的 `AuthenticationManager` Bean，否则使用 `AuthenticationConfiguration` 构造的全局管理器 |
| `UserSecurityVersionProvider` | 按 `UserDetails.getUsername()` 查询当前安全版本；用户是否启用由 `UserDetails` 提供，状态变化时宿主可撤销相关会话 |
| Spring Security `JwtEncoder` / `JwtDecoder` 与 Nimbus `JWKSource<SecurityContext>` | 优先使用框架接口；宿主可提供自己的编码器/解码器、JWKSource，也可用配置属性指定外部 PKCS#8 私钥和 X.509 公钥 PEM 文件 |
| `UserSessionStore` | 原子建立 Token family、刷新令牌轮换、重放检测、单族/全用户撤销与会话查询；仅保存刷新令牌哈希。JDBC/Redis 适配器在独立模块中实现 |
| MFA 策略、凭证与挑战存储接口 | 实现 MFA 时再按原子性和敏感数据保护边界定义；不为每个因子重复造 Repository |
| 因子验证器及秘密保护接口 | 仅为需要不同协议或可恢复秘密的因子提供；复用统一绑定/挑战生命周期，不预建空 SPI |
| Email 发送接口 | Email MFA 实现时由宿主提供发信能力；核心不绑定邮件服务 |
| EVM 签名验证接口 | 钱包 MFA 实现时隔离签名协议与地址归属策略；不提前绑定钱包库、链节点或厂商 |
| Spring Security `ClientRegistrationRepository` / OAuth 用户服务 | OAuth2/OIDC 实现时沿用 Spring Security Client 扩展点，动态注册由宿主适配数据库 |
| 联合身份映射扩展 | 基于 `(issuer, subject)` 查找稳定关联，并通过宿主 `UserDetailsService` 加载本地用户；沿用接入应用的用户模型 |
| 认证事件与错误处理 | 沿用 Spring Security 原生认证事件和 `AuthenticationFailureHandler` 等扩展点；Starter 不定义自己的事件发布机制，响应格式由宿主决定 |

接口只在消费者和实现边界明确后进入公共 API。每个持久化接口需定义原子性、异常和安全失败行为；启用某项能力却缺少其必需实现时，应明确启动失败或拒绝该能力，不能静默降级到不安全实现。会话存储由自动配置根据可用基础设施选择：宿主 `UserSessionStore` 优先，其次 JDBC（需 `JdbcTemplate` 和事务管理器），再到 Redis（需 `StringRedisTemplate`）；两类存储同时可用时 JDBC 优先。均不可用时启动失败，不退化为内存存储。

### 当前已实现的 Token 会话核心

- `JwtTokenIssuer` 签发短期 RS256 Access Token，subject 使用 `UserDetails.getUsername()`（本项目约定为邮箱）；Spring Resource Server 的 `JwtDecoder` 校验签名、issuer、audience 和有效期。
- `UserSessionService` 创建会话、轮换刷新令牌、撤销一个或全部会话、查询活动会话。`auth.security.jwt.refresh-enabled=false` 时仍创建会话，只签发 Access Token，会话到期时间等于 Access Token 到期时间，存储不写入 Refresh Token 哈希。启用刷新时令牌为 256 位随机 opaque 值，服务仅把 SHA-256 哈希交给 `UserSessionStore`。会话存储认证时间和认证方式，刷新后继续沿用原始 `auth_time` 与 `amr`，不会把刷新误报为用户重新认证。新会话记录客户端 IP 与由 `ua-parser/uap-java` 解析出的浏览器和操作系统摘要；解析输入最多 512 个字符，不持久化原始 User-Agent。并发会话策略由 `UserSessionConcurrencyPolicy` 按用户名提供；默认无限制，达到配置上限时可拒绝新会话或原子撤销最早会话。JDBC 用可串行化事务、Redis 用 Lua 保证容量检查和创建原子执行。
- Starter 默认实现通过 Spring Bean 条件装配，接入应用可提供对应接口 Bean 替换。`DefaultUserSessionClientInfoDetailsSource` 公开为可继承类，允许只覆盖客户端 IP 或设备摘要解析；令牌会话服务通过 `UserSessionService` 接口整体替换，内部实现不作为继承 API。
- `AuthSecurityConfigurer` 是 final 的 Spring Security DSL 组件，接入方无需继承；密码认证、认证失败处理、客户端信息和 Token 服务分别通过 Spring Security 原生认证管理器/提供器、`AuthenticationFailureHandler`、`AuthenticationDetailsSource` 与 Token 接口替换。登录和刷新成功分别通过具名 Bean `authSecurityLoginSuccessHandler` / `authSecurityRefreshSuccessHandler` 使用原生 `AuthenticationSuccessHandler` 替换；默认实现分别是登录 `TokenAuthenticationSuccessHandler` 和刷新 `RefreshTokenAuthenticationSuccessHandler`。登出撤销和响应分别通过 `authSecurityLogoutHandler` / `authSecurityLogoutSuccessHandler` 使用原生 `LogoutHandler` / `LogoutSuccessHandler` 替换；默认实现 `UserSessionLogoutHandler` 和 `UserSessionLogoutSuccessHandler` 可继承，也可直接提供上述原生接口实现。登录和刷新请求转换分别由独立的 `JsonLoginAuthenticationConverter` / `JsonRefreshTokenAuthenticationConverter` 实现原生 `AuthenticationConverter` 接口；自定义过滤器可直接复用或继承。`RefreshRequestAuthenticationToken` 是独立的刷新认证类型。若默认请求/响应协议不适用，接入方应使用 Spring Security 原生过滤器在自己的 `SecurityFilterChain` 中组合，而不是继承该 configurer。
- 登录端点异常通过 Spring Security `AuthenticationFailureHandler` 扩展；会话创建异常也进入同一处理器。会话创建是签发 Token 的功能步骤，不额外触发审计回调。认证成功/失败事件沿用 Spring Security 原生 `AuthenticationEventPublisher` 能力；Starter 不新增自己的事件类型或发布器。认证事件不代表后续会话创建成功；登出过滤器的 `LogoutSuccessEvent` 也不保证会话撤销成功。需要审计刷新或登出最终结果时，由宿主替换原生 `AuthenticationSuccessHandler`、`AuthenticationFailureHandler`、`LogoutHandler` 或 `LogoutSuccessHandler`，或在宿主提供的 `UserSessionService` 实现中记录。其他 API 的未认证/拒绝访问响应由宿主在 `SecurityFilterChain` 配置 `AuthenticationEntryPoint` 与 `AccessDeniedHandler`。
- 默认 Spring Security `AuthenticationDetailsSource` 只读取 Servlet 网络对端地址并忽略转发头。反向代理部署应由接入应用替换该 Bean，并仅在直接对端属于可信代理时解析并信任转发链；不得接受任意客户端提交的 `X-Forwarded-For`。会话存储实现需持久化新增的 `clientIp` 与 `device` 字段。
- JDBC 适配使用 `user_sessions` 与 `user_session_refresh_tokens` 保存会话及刷新凭证。配置正数并发会话上限时，额外使用 `user_session_creation_lock` 中唯一协调行，在事务内串行化会话创建，覆盖用户首次并发登录的空记录场景；代价是受限创建会跨用户串行。轮换按会话行加锁并在同一事务中消费旧哈希、插入新哈希和更新会话。DDL 由接入应用的迁移工具执行；过期家族按绝对过期时间清理，先删 refresh token 记录再删 session 记录。
- Redis 适配使用 `StringRedisTemplate` 和 Lua 原子脚本，创建、轮换、重放撤销、单会话和全部会话撤销均原子执行；消费标记保留到家族绝对过期以支持重放检测。当前所有 Redis key 使用相同 Cluster hash tag，能在 Cluster 中保证脚本原子性，但写入集中在单 slot；需要横向扩展时应先扩展 `UserSessionStore` 的原子分区契约，不能移除原子性要求。
- Store 的 `rotate` 必须是原子操作；重放已消费刷新令牌时撤销整个 family，不安装替换令牌。并发重复提交按重放处理，会话家族失效。
- Refresh TTL 不得超过绝对 TTL；存储实现必须强制过期、撤销和绝对寿命边界。启用 Token 服务时，接入应用须提供 `UserDetailsService` 和 `UserSecurityVersionProvider`，并通过 JDBC/Redis 适配模块或自有实现提供 `UserSessionStore`。默认 Nimbus JWT 路径使用宿主 `JWKSource<SecurityContext>`、配置的 RSA PEM 文件，或自有 `JwtEncoder`/`JwtDecoder`；Starter 不要求同时提供这些密钥来源。
- Access JWT 是无状态的：撤销 family 会立即阻止后续 refresh，但已签发 Access Token 默认仍可用到其短期过期。若要求即时拒绝，需要接入资源服务器侧按 `sid` 查询会话/安全版本的校验器；当前尚未提供该校验器。
- `UserSecurityVersionProvider` 版本变化会在刷新时撤销对应会话并拒绝新 Token。账号禁用状态同时由 Spring `UserDetails` 标记，刷新时重新加载并检查；宿主仍需在密码、MFA 或身份关联等安全变更时递增安全版本或撤销会话。

当前已暴露可选的过滤器 configurer `AuthSecurityConfigurer`，由宿主使用 `http.with(authSecurityConfigurer, Customizer.withDefaults())` 显式加入自己的安全链；Starter 不自动注册 `SecurityFilterChain`。登录、MFA 验证与刷新使用 Spring Security `AuthenticationFilter`，登出及全会话登出使用 `LogoutFilter`。过滤器不使用 Cookie；宿主仍须按自身链规则 permit 这些 POST 路由，并为这些无 Cookie 认证接口配置 CSRF ignore（或在纯 Bearer API 链中关闭 CSRF）。MFA 默认关闭；仅已绑定且被允许的因素会触发 pending 登录事务；未绑定用户直接通过密码登录。事务存储和因素 `AuthenticationProvider` 由宿主提供。

## 6. 配置模型与默认端点

### 配置来源

MFA 系统策略（总开关、可用因素及适用范围）的默认实现读取配置文件；宿主提供 `MfaPolicyProvider` Bean 时，自动配置回退并整体采用宿主策略，不与配置驱动策略逐字段合并。没有配置策略且没有该 Bean 时 MFA 关闭。RP ID、Origin 等协议参数由相应静态配置提供；宿主如需数据库运行时策略，可在 `MfaPolicyProvider` 实现中读取数据库。OAuth Client Registration 使用运行时配置源。用户凭证和一次性挑战是可变运行状态，不以应用配置文件作为其存储；由宿主存储 Bean 承载，后续是否提供 JDBC/Redis 适配按实际需求决定。宿主 `MfaPolicyProvider` 返回该用户已绑定且允许用于登录的 MFA 因素；Starter 不支持按 `UserDetails`、`GrantedAuthority` 或业务规则强制 MFA。MFA 成功不授予业务权限，API 授权仍由宿主的 Spring Security 规则负责。默认 JWT 不包含角色/权限 claim；需要授权 claim 的应用由宿主自定义 Token 签发及 Resource Server 映射。数据库中的 Client Secret 等秘密必须使用外部密钥加密；加密根密钥从 KMS/Vault/宿主 `SecretProtector` 提供，不能与密文同库明文保存。

`@ConfigurationProperties` 可承载 MFA 静态系统策略，默认关闭；宿主提供 `MfaPolicyProvider` Bean 时，后者整体替换配置驱动策略，二者都没有时 MFA 关闭。默认 JWT 功能启用；Nimbus 编码器/解码器通过 JWKSource 获取密钥；密钥来源可由宿主提供 JWKSource、使用外部 PEM 文件路径生成默认 JWKSource，或直接提供 Spring `JwtEncoder` 和 `JwtDecoder`。不要用 YAML 保存真实密钥内容；密钥文件由外部密钥管理设施挂载并限制读取权限。数据库运行时策略由宿主 Bean 负责一致性；OAuth 配置更新时允许进行中的 state/nonce 回调按原注册版本完成或明确失效。

### 建议端点

所有路径可通过 `auth.security.endpoints.*` 配置。登录、会话、单会话登出和全部会话登出随 Starter 安全能力启用；`auth.security.jwt.refresh-enabled` 只控制是否签发 Refresh Token 并安装刷新过滤器。路由冲突由宿主安全链和应用路由配置负责，不应悄悄覆盖宿主业务路由。

| 用途 | 默认路径/方法 |
|---|---|
| 本地邮箱登录 | `POST /api/auth/login` |
| 查询 MFA 可用方式 | `GET /api/auth/mfa/options` |
| MFA 登录挑战/验证 | `POST /api/auth/mfa/challenge`、`POST /api/auth/mfa/verify` |
| 刷新 Token | `POST /api/auth/refresh` |
| 当前会话登出 | `POST /api/auth/logout` |
| 全部会话撤销 | `POST /api/auth/logout-all` |
| 查询会话 | `GET /api/auth/sessions` |
| 撤销指定会话 | `DELETE /api/auth/sessions/{sessionId}` |
| 当前用户 MFA 设置/绑定/确认/解绑/恢复码 | `/api/me/mfa/**` |
| OAuth 登录开始 | `GET /oauth2/authorization/{registrationId}` |
| OAuth 回调 | `GET /login/oauth2/code/{registrationId}` |
| OAuth 一次性兑换 | `POST /api/auth/oauth2/exchange` |
| JWT 公钥 | `GET /.well-known/jwks.json`（启用 Token 签发并配置 JWKSource 时提供，仅公开 RSA 验签公钥） |

默认 YAML 只包含静态部署参数，不含密钥和 DB 动态配置：

```yaml
auth:
  security:
    enabled: true
    jwt:
      issuer: ${AUTH_TOKEN_ISSUER}
      audience: ${AUTH_TOKEN_AUDIENCE}
      access-ttl: 10m
      refresh-enabled: true
      refresh-ttl: 14d
      refresh-absolute-ttl: 30d
    remote-login:
      enabled: false
    endpoints:
      base-path: /api/auth
      login: /login
      mfa-verify: /mfa/verify
      refresh: /refresh
      logout: /logout
      logout-all: /logout-all
```

配置类使用 Bean Validation 校验：Token 有效期必须为正，刷新有效期不能超过绝对有效期；启用 Token 签名时 `issuer` 和 `audience` 必填，密钥可通过外部 PEM、JWKSource 或 Spring `JwtEncoder`/`JwtDecoder` 提供。当前没有 Access Token 最大 TTL 配置，接入应用应按自身风险要求限制有效期。Cookie 模式（若将来加入）必须强制 HTTPS 和精确 Origin。端点路径应检查绝对/相对格式及相互冲突。DB 配置写入则单独通过应用管理服务验证、版本化和审计。

异地登录检测和通知默认关闭。开启后，默认登录成功处理器在写出 Token 响应后调用接入方提供的 `RemoteLoginHandler`，传递用户名、客户端 IP/设备和会话 ID；不传递 `UserDetails`、凭证或 Token。IP 到地点的解析、与历史位置的比较及通知投递均由接入方实现。自定义登录成功处理器须自行组合该扩展点。通知失败不得撤销已签发 Token，处理器应避免同步阻塞登录请求。

## 7. JWT、Refresh Token 与会话

### 签发和验证

1. 登录主凭证验证成功后，若用户没有已绑定且启用的 MFA 因素，则直接创建会话并签发短期 Access JWT；若存在可用因素，则只创建短时 pending 事务，验证成功后才创建会话并签发 JWT。
2. Access Token 由 Spring `JwtEncoder` 签发；默认 Nimbus 实现使用 JWKSource 选取 RS256 签名键并验证 issuer、audience 和时间声明。默认单密钥源使用公钥指纹作为 `kid`；多密钥源必须配置 `auth.security.jwt.active-key-id`，并确保该值匹配当前签名密钥。API 使用 Spring Security JWT Resource Server 验证签名。不要自建 JWT 解析过滤器。
3. Refresh Token 是 CSPRNG 产生的高熵不透明随机值；HTTP 响应体返回，存储仅保存不可逆哈希、family、用户、安全版本、过期时间、轮换状态和必要设备元信息。
4. Refresh 请求在存储事务中验证当前 token 哈希且未使用，再原子标记旧 token 已消费并创建新 token。同一旧 token 的并发提交中只有一个轮换操作能成功；其他提交被识别为重放并撤销 family。发生这种并发时，先成功轮换的请求可能已经签发短期 Access Token，但该 family 已撤销，后续刷新会失败；Access JWT 仍遵守无状态验证语义，默认有效到自身过期。客户端应对刷新请求做 single-flight，避免正常并发请求触发重放处理。
5. 客户端对刷新请求做 single-flight，避免并发页面/API 请求重复刷新。服务端不为重复刷新宽限返回相同明文 Token。

轮换结果在 HTTP 响应写出前已提交到存储。若服务在提交后发生故障或响应丢失，客户端无法恢复新 Refresh Token；重试旧 Token 会被视为重放并撤销该会话 family，用户需要重新登录。当前不提供重复请求幂等恢复。

### 过期、撤销和失效

- Refresh JWT 不采用长期不可撤销自验证形式。Session family 记录是续期和撤销的权威来源。可撤销 opaque Refresh 的代价是每次续期需共享存储；这是可接受的安全/可用性权衡。
- 当前登出撤销当前 family；logout-all 撤销该用户所有 family；会话查询返回不敏感元信息，不能返回完整 Token。
- 禁用用户、密码/主凭证变更、MFA 凭证/恢复信息变更、身份关联撤销和高风险安全事件应由宿主调用会话服务撤销 family，或通过 `UserSecurityVersionProvider` 提升 token version；这会阻止后续刷新。会话撤销/版本提升本身不保证无状态 Access Token 即时失效；即时拒绝要求资源服务器逐请求检查共享会话状态或用户安全版本，否则已签发的 Access Token 最迟在其 TTL 到期后失效。
- 即时 Access Token 撤销需要每次请求访问共享 denylist/session state 或检查用户安全版本；这会引入延迟和存储故障影响。推荐在严格即时撤销模式下 fail-closed。若只检查签名与过期，撤销上界为 Access TTL，应明确告知宿主。
- 并发会话策略通过 `UserSessionConcurrencyPolicy` 扩展；默认最大活跃会话数为 0（无限制），可配置超限时拒绝新会话或原子撤销最早会话。自定义 `UserSessionStore` 必须覆盖带策略的原子创建方法，否则启用正数上限时会 fail-closed。

### 密钥来源和泄露响应

禁止代码、示例、默认配置或测试 fixture 带可用于生产的硬编码私钥。默认 Nimbus 路径支持宿主提供 `JWKSource`，或通过配置指定外部未加密 PKCS#8 RSA 私钥与匹配的 X.509 RSA 公钥文件（至少 2048 位）；文件方案在启动时加载单个密钥对，不支持运行时热加载。也可由宿主直接提供 Spring `JwtEncoder`/`JwtDecoder`，用于 KMS/HSM 等不可导出密钥。`JWKSource` Bean 优先于文件路径。多实例须共享一致的验签公钥集合。推荐 RS256，私钥仅签名服务可访问，JWKS 可发布公钥。

Starter 不实现密钥生成、轮换调度、运行时激活或泄露处置。宿主可通过替换 `JWKSource` 扩展验签公钥集合；若要动态切换签名密钥，还应替换 `JwtTokenIssuer`，必要时替换 `JwtEncoder`/`JwtDecoder`。宿主负责轮换顺序和各验证方的密钥缓存传播。建议先发布新公钥并确认验证端可见，再切换签名 `kid`；旧公钥至少保留到最长 Access Token TTL、时钟偏差和缓存刷新窗口之后。发现泄露时，宿主负责停止使用该键、从信任集合移除对应 `kid`、刷新验证方 JWKS 缓存、撤销受影响会话，并按事件范围要求重新认证。

JWKS 端点固定为 `GET /.well-known/jwks.json`，在 JWT 启用且存在 JWKSource 时注册，只发布用于 RS256 验签的 RSA 公钥。多密钥必须具有唯一 `kid`，JWT 头中的 `kid` 由 `active-key-id` 选择。宿主须在自有 `SecurityFilterChain` 中允许该路径匿名访问；Starter 不创建安全链，也不发布 OIDC Provider Metadata。

### 前端和跨域

本方案的 Refresh Token 由响应体传递，避免默认跨域 Cookie 与隐式 CSRF 耦合，但 JS 可读长期凭证仍会受 XSS 窃取。SPA 推荐短暂保存在内存、使用 CSP 与严格依赖治理；不要默认 localStorage。若接入方选择 Refresh Cookie，必须另行启用 Secure、HttpOnly、明确 SameSite、精确 CORS `allowCredentials(true)`、CSRF Token/Origin 校验和 TLS；不能认为 CORS 就是 CSRF 防护。Bearer Header 模式使用精确 CORS Origin allowlist、`allowCredentials(false)`，浏览器状态改变请求仍不得从 Cookie 接受身份。

## 8. MFA 状态机与因子

MFA 默认关闭。当前提供已绑定 MFA 用户的 pending 登录响应、`/mfa/verify` 过滤器、TOTP RFC 6238 服务与 Spring `AuthenticationProvider`，以及 TOTP 状态、绑定、确认和验证解绑过滤器。事务 Store 和加密 TOTP 凭证 Store 由宿主实现；宿主在自有 `SecurityFilterChain` 中授权管理路径。其他因子和配置管理尚未实现。完整状态模型、端点规划、因子要求和未决事项见 [MFA 实现方案](mfa-implementation-plan.md)。BIP-39 助记词按常规 MFA 因子处理，仅用于主认证后的二次验证。

关键约束：默认关闭；用户可移除最后一个因素；绑定和移除通过对应因素的验证码确认；变更 MFA 不撤销会话或强制退出；不提供强制 MFA 或无因素用户的首次绑定登录事务；待完成 MFA 不能访问业务 API，也不能创建完整会话或签发 Token；成功后复用现有 `UserSessionService`；Starter 不管理权限且 MFA 不替代 API 授权；系统策略管理 API 由宿主负责，当前用户管理路径使用 `/api/me/mfa`；不采用 Spring Security 7 内建 MFA 编排，不新增 Starter 自有事件发布机制。

## 9. OAuth2/OIDC 客户端登录

采用 Spring Security OAuth2 Client/OIDC Login 实现授权发起、回调、state/nonce 校验和 ID Token 验证；支持动态 `ClientRegistrationRepository` 从 DB 加载 provider 配置。优先 OIDC；只有必要时才对纯 OAuth2 provider 使用专门用户信息映射。Client Secret 不写入代码/YAML/仓库，密文由 `SecretProtector` 加密，根密钥来自外部安全设施。

```text
SPA -> GET /oauth2/authorization/{registrationId}
     -> Starter 产生并保存一次性 state、OIDC nonce 和注册配置版本
     -> 第三方 IdP 授权
IdP -> GET /login/oauth2/code/{registrationId}?code=...&state=...
     -> Spring Security 校验 state/nonce、交换授权码并验证 OIDC 身份
     -> 联合身份映射扩展根据稳定 (issuer, subject) 查找已关联的本地邮箱
     -> 首登：仅按已验证邮箱关联既有本地用户；无匹配/冲突时拒绝自动关联
     -> 若本地用户已绑定允许的 MFA 因素则完成后续验证，否则直接继续
     -> 若用户已绑定允许的 MFA 因素，先完成 MFA；否则直接产生短时、一次性 OAuth login exchange code
SPA -> POST /api/auth/oauth2/exchange { code }
     <- 本系统 Access JWT + Refresh Token 响应体
```

禁止把 JWT 或 Refresh Token 放在 redirect URL、query 或 fragment。OAuth 回调后通过短时、随机、绑定 state/目标 SPA allowlist 且单次消费的 exchange code交付令牌。OAuth 状态/nonce 由共享短期存储保存，集群回调必须能读到发起节点状态。

邮箱关联策略：首次外部身份只有在可信 IdP 明确声明邮箱已验证且与现有本地邮箱唯一匹配时才允许按已确认方向进行关联；缺失/未验证/冲突必须拒绝并返回不泄露账号存在性的错误或交由宿主人工流程。关联后以 `(issuer, subject)` 为稳定身份键；后续邮箱变化不触发重新匹配或自动迁移。不得只靠相同邮箱解绑/覆盖已有外部身份。账号停用时拒绝登录且撤销/阻止会话。解绑由宿主要求本地强认证及其业务确认策略。

OAuth 登录共享本地用户 MFA 策略。IdP 的 MFA 声明只有在 issuer、claim 语义和 assurance 映射明确配置且验证可信时才能作为本地因子证明；默认不把 IdP 的登录视为本地 MFA 完成。第三方 Access/Refresh Token 默认不存、不转发、不作为本系统 JWT。

## 10. API DTO、错误与 Spring Security 扩展点

- 登录/刷新/MFA/OAuth exchange 使用明确的 request/response DTO，由 Security Filter 转换和序列化；不将实体、内部异常或认证框架对象直接序列化。不为登录、登出、刷新增加 MVC Controller。
- 成功响应示例字段：`accessToken`、`tokenType`、`expiresIn`、`refreshToken`、`refreshExpiresIn`、`sessionId`、必要的 `mfaRequired`/`challengeId`。pending MFA 响应不得含完整权限 Token。
- MVC 异常由宿主 `@ControllerAdvice` 处理；Security Filter 异常由宿主配置的 Spring Security 处理器处理。Starter 认证过滤器的默认失败行为只设置通用状态和 `no-store` 响应头，不固定响应体格式；Bearer 401 保留 `WWW-Authenticate`。
- 错误类别需区分未认证、MFA 未完成、Token 无效/过期、Refresh 重放、外部 IdP 失败、策略拒绝；对外错误不得泄漏邮箱是否存在、因子是否启用、密码/OTP 正误或第三方详细响应。
- 若宿主选择 JSON 错误响应，由宿主的 `AuthenticationFailureHandler`、`AuthenticationEntryPoint`、`AccessDeniedHandler` 或 MVC 异常处理器生成；Starter 不增加错误 DTO 或错误映射器。
- Starter 不定义自己的生命周期事件或通用事件发布机制。宿主可沿用 Spring Security 原生认证事件，并在宿主拥有的服务/处理器中实现其业务审计与观测；敏感凭证不得进入事件、日志或指标。
- Starter 不提供自定义计数接口，也不绑定 Micrometer 厂商实现；观测由宿主按自身安全与指标规范负责。

## 11. 安全责任分工

### 当前代码已提供

- JWT 签发/验证集成、Refresh 家族轮换与撤销 SPI、会话 DTO/服务。
- 登录、登出、全部会话登出过滤器集成；Refresh Token 签发和刷新端点可通过 `auth.security.jwt.refresh-enabled` 整体启停。
- 条件化 Boot 自动配置、类型安全配置；会话存储可由宿主实现，或通过独立模块选择 JDBC/Redis 适配。

### 规划中，当前未实现

- MFA 具体因子及凭证管理、OAuth2/OIDC Client 登录适配。
- MFA、WebAuthn、EVM 可选模块。

### 接入应用必须提供

- 用户 ID、邮箱规范化/唯一性、用户加载、主凭证校验、停用状态、业务授权与角色/租户映射。
- 生产密钥提供器、密钥轮换/KMS 权限、数据库/Redis 生命周期、凭证加密实现、备份与恢复。
- 邮件发送；钱包归属与智能合约钱包规则；助记词安全预生成、交付与丢失恢复流程。
- CORS 精确 allowlist、TLS/代理头信任、Cookie/CSRF 策略、OAuth 回调 URI/SPA redirect allowlist 和客户端密钥供给。
- OAuth 邮箱验证信任、账号冲突人工处理、身份解绑及业务级安全事件审计。
- 自定义 `SecurityFilterChain` 时显式接入认证过滤器/Resource Server/异常处理，不假设 Starter 覆盖宿主安全链。

## 12. 测试与验证计划

按行为选择最窄测试：无 Spring 领域逻辑用单元测试；属性校验/自动配置用 ApplicationContextRunner 或对应 Boot 测试支持；HTTP 响应行为使用对应的过滤器或 MVC 测试支持；DB 并发与原子轮换用生产数据库引擎的容器集成测试；仅少量全应用启动和代表性 HTTP 测试。固定时钟、挑战值和随机源边界以确保可重复。

分阶段验收重点：

1. **工程/API 骨架**：多模块依赖方向、BOM、自动配置导入元数据、无默认兜底 SecurityFilterChain、配置绑定和校验、端点替换/禁用/冲突测试。
2. **Token/会话**：签名/issuer/audience/过期/多 kid；刷新原子轮换；并发仅一个胜者；旧 Token 重放撤销 family；登出/全登出/用户禁用和安全版本变化；存储不可用时 fail-closed 行为。
3. **MFA**：pending 状态不能访问受保护 API；一次性挑战；TOTP 确认绑定、时间步重放；WebAuthn origin/RP/challenge 校验；Email 用途绑定；恢复码单次消费；助记词敏感字段不出现在日志/DTO。
4. **OAuth**：动态注册绑定、授权 state/nonce 错误和重放、OIDC issuer 验证、邮箱已验证/未验证/冲突映射、停用用户、exchange code 单次消费和 redirect allowlist。
5. **存储/样例**：JDBC 迁移和真实数据库集成；Redis 原子脚本/并发验证；接入样例不含硬编码凭证，含自定义 `SecurityFilterChain` 集成方式。

发布前使用仓库 Maven Wrapper 执行 `./mvnw verify` 及技能要求的安全检查清单。此文档写入本身不代表以上测试或构建已执行。

## 13. 实施阶段

1. 创建父工程、BOM、core、autoconfigure、starter、sample；确定 API、类型安全配置、条件装配和端点契约。（已完成）
2. 实现 JWT/JWKS 能力、刷新 Token 家族状态机、会话管理 SPI，再实现 JDBC/Redis 存储适配和并发测试。（JWT RS256 签发/验证、JWKS 端点、刷新会话服务、并发会话策略及 JDBC/Redis 适配已实现；以实际验证结果为准）
3. 实现 MFA 公共流程和首批已确认登录因素；模块拆分以独立依赖或独立发布需求为依据，不按因子类型预建模块。BIP-39 助记词作为常规 MFA 因子实现，不用于主登录或账号恢复。
4. 使用 Spring Security OAuth2/OIDC Client 实现动态数据库注册、基于 `(issuer, subject)` 的本地用户映射和一次性 exchange 流程；映射结果由宿主 `UserDetailsService` 提供，不引入 Starter 自有用户 ID 类型。
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
