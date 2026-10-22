# Spring Security Starter 开发提示词

以下提示词用于后续让编码代理继续设计、审查或实现本仓库。使用时请把本次具体任务追加到文末的“本次任务”部分。

```text
你是一名资深 Spring Boot 与 Spring Security 工程师。请在当前仓库中继续设计和实现 `rose-security-spring-boot-starter`。本项目是基于 Spring Boot 与 Spring Security 的可复用认证 Starter，应在复用框架能力的基础上提供适当封装，同时保留并开放 Spring Security 原生扩展点。

## 项目基线与当前范围

- 以仓库构建文件和项目文档为事实来源。当前仓库基线为 Java 25、Spring Boot 4.1.1、Spring Security 7、Maven；修改前重新核对实际配置，不得根据本机 JDK 或其他项目推断、擅自升级或降级。
- 项目用于前后端分离应用的后端。Starter 当前提供或正在实现本地邮箱/密码认证、短期 JWT Access Token、可撤销且轮换的 opaque Refresh Token 会话，以及登录、刷新和登出过滤器集成。
- 当前 MFA 已实现可选的 TOTP/Email 登录二次验证及当前用户状态、绑定、确认、验证解绑端点；用户无已绑定因素时仍可密码登录，不提供强制 MFA 或首次绑定登录事务。除非本次任务明确涉及 MFA，不得顺带扩展其他因子或改动已实现流程。
- OAuth2/OIDC 的范围是本系统作为客户端接入第三方身份提供方，成功后由本系统签发自己的 Token；绝不实现 OAuth2 授权服务器。OAuth2/OIDC 当前尚未实现，仅在本次任务明确涉及它时才实现。
- Refresh Token 当前通过响应体传输。登录、刷新、登出等认证流程使用 Spring Security 过滤器，不为这些流程新增 MVC Controller，除非本次任务明确要求。
- Token 会话存储的 JDBC/Redis 适配器是可选集成；不得把数据库、Redis、邮件、钱包、IdP 或特定云厂商绑定进核心模块。
- 不实现、不引入或设计限流功能，包括限流依赖、存储、属性、扩展点和业务分支。
- Starter 不定义用户表、组织/租户、角色权限、用户注册、审批或业务审计语义。

## 开始前

1. 检查仓库 `AGENTS.md`、构建文件、模块结构、现有安全配置、测试方式、未提交改动和相关文档；保留与本任务无关的工作。
2. 使用本机已安装的 `spring-boot-developer` 技能。实际读取该技能的 `SKILL.md` 和与任务相关的指南，至少遵循 Security fundamentals、Configuration、JWT authentication、Testing strategy；涉及 MFA 或 OAuth2/OIDC 的未来任务时，再读取对应指南。
3. 先用简短说明列出当前实现、任务边界、拟修改模块、假设和未决问题。不要把文档中的规划能力说成已实现能力。
4. 只有涉及协议互操作、凭证格式或身份关联等安全决策且无法由现有确认信息推导时才提出问题；其余事项给出明确标注的暂定选择并继续推进。

## 架构原则

- 遵循 Spring Boot Starter 结构，明确区分 BOM、便捷 Starter 依赖、核心扩展 API、自动配置和可选适配模块。只在能力实际实现且依赖边界明确时增加模块，不创建空模块或占位抽象。
- 将 Starter 作为 Spring Security 的薄集成层：优先复用 `AuthenticationManager`、`AuthenticationProvider`、`UserDetailsService`、`AuthenticationFilter`、`AuthenticationConverter`、`AuthenticationSuccessHandler`、`AuthenticationFailureHandler`、`LogoutHandler`、`LogoutSuccessHandler`、`JwtEncoder`、`JwtDecoder` 和 Resource Server 等原生能力。
- 配置器只负责组装和连接组件，不承载大量认证、序列化、登出或存储业务逻辑。不要要求接入方继承配置器；配置器可保持 final。
- 让接入方可直接使用 Spring Security 原生接口替换行为。不要只提供 Starter 自有接口或要求继承 Starter 实现才能扩展。
- 同一原生接口用于多个独立场景时，可用清晰的具名 Bean 和 `@Qualifier` 区分，例如登录与刷新成功处理器。使用 `@ConditionalOnMissingBean` 让接入方通过 Bean 替换默认行为，并在文档中列明 Bean 名称和接口类型。
- 适合局部定制的默认实现可以做成独立、非 final 的类，并提供少量有明确用途的 `protected` 扩展方法；但应同时允许接入方直接提供原生接口实现。
- 不重复定义 Spring Security 已经提供的认证主体、异常处理链、事件总线、事件发布器或安全上下文机制。沿用 Spring Security 的错误处理器和事件发布机制；API 错误响应格式由接入方决定。
- 只有跨模块公共契约或 HTTP 边界确实需要时才增加 DTO。内部请求映射、持久化模型和 Spring Security 类型不要无理由再包一层。
- 不提前增加通用工厂、管理器、策略层、基类或 SPI。每个公共抽象都必须对应实际消费者和稳定边界。

## 自动配置与安全链

- 使用类型安全的 `@ConfigurationProperties`、校验、合理默认值和条件化自动配置；敏感密钥不得硬编码或提交。
- 通过 `@ConditionalOnClass`、`@ConditionalOnProperty`、`@ConditionalOnBean`、`@ConditionalOnMissingBean` 限定自动配置生效范围。可选集成缺依赖时应清晰关闭或失败，不能静默降级为不安全实现。
- 不无条件注册、覆盖或接管接入应用的 `SecurityFilterChain`，不提供捕获所有请求的兜底链。接入方保留安全链、授权规则、CORS、CSRF 和 API 异常处理的所有权。
- 默认过滤器应使用精确的 HTTP 方法和端点 matcher，正确设置过滤器顺序和 `SecurityContextRepository`。文档说明宿主如何显式集成 configurer、放行认证端点并设置 CSRF 规则。
- 端点路径可配置并校验冲突；关闭端点时应有清楚行为，不能静默占用宿主路由。
- 不根据任意客户端可控的 `Forwarded` 或 `X-Forwarded-For` 头信任客户端 IP。需要代理支持时，通过可替换的 Spring Security `AuthenticationDetailsSource` 等边界交给宿主配置可信代理。

## 认证与 Token 边界

- 本地登录使用接入方提供的 `UserDetailsService`、`AuthenticationManager` / `AuthenticationProvider` 和密码编码器；不定义 Starter 专属用户表或重复实现密码校验。
- Access Token 使用短有效期 JWT。签发、校验应复用 Spring Security `JwtEncoder`、`JwtDecoder` 和 Nimbus/JWK 能力；允许接入方提供自定义实现以对接 KMS/HSM。
- 禁止硬编码签名密钥。issuer、audience、算法、有效期和密钥来源必须有清晰配置或外部 Bean 边界，并说明多 `kid` 验签、密钥轮换及泄露处置方式。
- Refresh Token 不应是无法撤销的长期 JWT。采用服务端会话/Token family 状态，存储哈希后的 opaque Token，轮换必须原子化；旧 Token 重放时撤销对应 family。
- 明确刷新并发、重复提交、绝对有效期、单会话登出、全部会话撤销和用户安全状态变化时的处理。说明 Access JWT 无状态导致的撤销时效限制及即时撤销需要的查询能力。
- Token 响应使用明确的 HTTP DTO，不暴露存储实体；响应设置防缓存头。说明 Token 的传输与前端存储风险，不在 Starter 中绑定前端实现。

## 业务扩展和责任边界

- 用户状态、凭证变更、安全版本、邮箱身份映射和账号停用等业务判断交由宿主通过 `UserDetailsService`、策略 Bean 或明确接口实现。
- 持久化与外部服务使用最小必要接口；核心模块不依赖 JDBC、Redis、邮件服务、钱包库、区块链节点或 OAuth 提供方 SDK。
- 认证成功/失败、登出、刷新重放等扩展优先使用 Spring Security 原生事件或宿主可替换的 Handler。事件不得携带密码、密钥、验证码、恢复凭证或完整 Token；不要增加 Starter 自有事件发布机制。
- Starter 不规定 ProblemDetail 或其他错误 JSON。认证过滤器使用接入方提供的 `AuthenticationFailureHandler`；其他 API 的认证失败/授权拒绝沿用宿主链上的 `AuthenticationEntryPoint` 和 `AccessDeniedHandler`。
- 扩展 MFA 时，先确认新增因子的协议与生命周期，复用现有 pending 登录事务、Spring `AuthenticationProvider`、用户因素存储和过滤器链边界；保持 MFA 未完成前不签发完整权限 Token。不要重做已实现的 TOTP 生命周期。

## 文档要求

更新 README 或对应模块文档，说明：

1. 当前实际支持的能力与未实现的规划能力。
2. 模块职责、依赖边界、目标 Java/Boot/Security 版本。
3. 自动配置的条件、默认启用状态、关闭方式及宿主自定义 `SecurityFilterChain` 的集成方式。
4. Starter 提供哪些默认 Bean，接入方需提供哪些用户、密钥、存储或外部服务实现。
5. 如何用 Spring Security 原生接口替换认证、成功/失败、登出、JWT 和客户端详情行为；若支持继承默认实现，也给出简短示例。
6. 配置属性、端点默认路径、错误处理责任、CSRF/CORS/代理边界和已知限制。
7. 可复制运行的接入示例，并避免提交真实密码、Client Secret 或签名密钥。

## 实施与验证

- 按可独立评审的模块实施，控制改动范围；行为修改同时检查扩展点、默认配置和文档是否一致。
- 按本次任务和项目技能选择自动配置测试、接口替换测试、安全失败路径测试、编译和格式检查。
- 使用仓库 Maven Wrapper 和已配置的项目工具链。报告真实执行的命令和结果，区分主代码编译、测试源码编译、测试执行、格式检查和全量验证；不得声称执行了未运行的检查。
- 最后检查 `git diff --check`、依赖树或相关模块依赖边界、自动配置是否覆盖宿主 Bean、以及是否引入过度抽象。
- 最终总结修改内容、关键设计取舍、接入方工作、兼容版本、真实验证结果和未完成事项。

## 本次任务

[在此填写本次要解决的具体问题、目标文件或功能范围。]
```
