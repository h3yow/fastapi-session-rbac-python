# FastAPI 会话认证与 RBAC 访问控制（本地可验证）

一个基于内存存储、可本地完整验证的会话认证 + 基于角色/权限的访问控制示例。
重点保证：**凭证生命周期、权限判定、异常尝试在多请求并发下一致且可解释**。

- 框架：FastAPI（无数据库，状态全部保存在带锁的进程内存储，重启即重置）
- 密码：PBKDF2-HMAC-SHA256（200000 轮）+ 每用户独立随机盐，恒定时间比较
- 会话：不透明随机令牌（`sid`，HttpOnly Cookie）+ 会话绑定 CSRF 令牌

## 1. 快速开始

```bash
uv sync
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
# 交互文档：http://127.0.0.1:8000/docs
```

运行全部测试（含并发与边界场景，日志打印关键输入与判定依据）：

```bash
uv run pytest                       # 汇总
uv run pytest -o log_cli=true       # 同时查看 INFO 级判定日志
```

种子账户（见 `app/container.py`）：

| 用户  | 密码        | 角色   | 有效权限                                         |
|-------|-------------|--------|--------------------------------------------------|
| admin | admin-pass  | admin  | article:read/write、admin:users、session:revoke |
| alice | alice-pass  | editor | article:read、article:write                      |
| bob   | bob-pass    | reader | article:read                                     |
| carol | carol-pass  | （无） | 直接授予 article:read                            |

## 2. 认证流程

### 2.1 登录 / 登出

- `POST /api/auth/login`，请求体 `{"username","password"}`。
  成功返回 `204`，并下发两个 Cookie：
  - `sid`：会话令牌，`HttpOnly; SameSite=Strict`，脚本不可读（缓解 XSS 窃取）；
  - `csrf_token`：CSRF 令牌，前端可读，后续写请求需放入 `X-CSRF-Token` 头。
- `POST /api/auth/logout`：撤销当前会话并清除 Cookie；无有效会话时也幂等返回。

### 2.2 会话生命周期（确定的过期与续期语义）

| 配置（`app/auth.py`） | 值     | 含义 |
|-----------------------|--------|------|
| `IDLE_TIMEOUT`        | 30 分钟 | 空闲超时；也是每次滑动续期的延长量 |
| `ABSOLUTE_TIMEOUT`    | 12 小时 | 绝对上限，自会话创建时刻起，无法通过活跃突破 |
| `LOCK_DURATION`       | 15 分钟 | 账户锁定时长（见第 4 节） |

- **空闲超时 + 滑动续期**：每次通过认证的请求，若距 `expires_at` 剩余时间
  `<= IDLE_TIMEOUT`，则把 `expires_at` 顺延一个 `IDLE_TIMEOUT`；不活跃超过
  30 分钟的会话立即失效（`session_expired`）。
- **绝对上限**：无论续期多少次，`expires_at` 永不超过 `created_at + 12h`。
  到达上限后返回 `session_expired`，需重新登录。
- 以上全部基于可注入时钟（测试中用 `FakeClock`），因此过期/续期/解锁时刻
  **确定且可复现**。

### 2.3 密码变更后既有会话必须失效

会话在创建时记录 `password_version`。修改密码
（`POST /api/auth/change-password`，需旧密码 + CSRF）会使该用户
`password_version + 1`，**所有既有会话（包括当前会话与其它并发会话）**
在下一次请求时因版本不匹配而失效，错误码：

```
session_invalidated_by_password_change
```

注意：改密**只**递增密码版本，不打“撤销”标记，因此“改密失效”与
“会话被独立撤销”（`session_revoked`）是两个可区分的判因。

### 2.4 多并发会话独立撤销

同一账户可同时拥有多个会话（如手机、网页）。每个会话有独立的 `sid`/CSRF：

- `GET /api/sessions`：列出本账户当前有效会话（标记哪个是 `current`）；
- `DELETE /api/sessions/{session_id}`：撤销指定会话。属主本人可撤销自己的
  任意会话；持有 `session:revoke` 权限者（管理员）可撤销他人会话；
  其余情况返回 `forbidden`。撤销一个会话不影响同账户的其它会话。

### 2.5 登录失败不暴露账户是否存在，但结果可区分

- “账户不存在”与“密码错误”返回**完全相同**的状态码（401）、错误码
  （`invalid_credentials`）与文案（`invalid username or password`），
  且两种情况都计入失败计数。
- 但“认证失败”（401 `invalid_credentials`）与“账户锁定”
  （423 `account_locked`）使用不同状态码与错误码，调用方与测试可明确区分。

## 3. 权限模型（RBAC，默认拒绝）

- 每个用户拥有**直接权限**集合与**角色**集合；
  角色到权限的映射在 `app/container.py` 的 `ROLE_PERMISSIONS` 中定义。
  有效权限 = 直接权限 ∪ 各角色权限（`RBACService.effective_permissions`）。
- **默认拒绝**：所有受保护资源都必须显式声明所需权限
  （依赖 `require_permission("xxx")`）；未登录 → `not_authenticated`，
  已登录但不满足 → 拒绝。
- **权限在线变更、立即生效**：`/api/admin/grant`、`/api/admin/revoke`
  直接修改内存中的用户记录，已有的后续请求（无需重登、无需重启）立即按新
  权限判定。角色变更（`grant_role/revoke_role`）同理。
- **两种拒绝原因可区分**：会话在登录时保存一份权限快照
  （`permission_snapshot`）——
  - 登录时就不具备该权限 → `forbidden`；
  - 登录时具备、但在当前请求前被撤销 → `permission_revoked`。

| 接口 | 方法 | 要求 |
|------|------|------|
| `/`、`/healthz` | GET | 匿名可访问（与原骨架 `{"Hello":"World"}` 行为兼容） |
| `/api/auth/login`、`/api/auth/logout` | POST | 匿名可访问 |
| `/api/profile` | GET | 已登录 |
| `/api/auth/change-password` | POST | 已登录 + CSRF |
| `/api/sessions` | GET | 已登录 |
| `/api/sessions/{id}` | DELETE | 已登录 + CSRF +（属主或 `session:revoke`） |
| `/api/articles` | GET | `article:read` |
| `/api/articles` | POST | `article:write` + CSRF |
| `/api/admin/grant`、`/api/admin/revoke` | POST | `admin:users` + CSRF |

## 4. 登录滥用控制：失败计数与锁定策略

- **维度**：`(账户名, 来源 IP)`，计数键 `username|source_ip`。
  不同 IP 的计数相互独立；对不存在账户同样计数。
- **阈值**：同一维度连续失败达到 `MAX_FAILURES = 5` 次时立即置锁。
  置锁的那一次尝试本身仍是一次失败，返回 `invalid_credentials`；
  其后的所有尝试直接返回 `account_locked`（423），**不再校验密码**。
- **解除条件（确定且可复现）**：锁定 `LOCK_DURATION = 15 分钟`。
  锁定期满后的**下一次请求**自动解除并清零计数——这是唯一解除途径；
  成功登录也会清零计数。不存在“越试越重置”或后台定时器带来的不确定性。
- **并发一致性**：失败计数的“读取—递增—判阈—置锁”全部在 `Store` 的同一把
  `RLock` 临界区内完成。因此并发失败不会丢失/冲掉计数，达到阈值后不可能被
  并发请求绕过（测试见 `test_concurrent_failures_cannot_bypass_threshold`：
  20 个并发错误密码，恰好 5 个 `invalid_credentials`、15 个 `account_locked`，
  计数稳定在 5；随后 10 个并发的**正确密码**也全部被 `account_locked` 拒绝）。

## 5. 跨站请求伪造（CSRF）防护

采用“双重提交 Cookie + 会话绑定”方案：

- 登录时服务端在会话内生成随机 `csrf_token` 并通过可读 Cookie 下发。
- 前端对所有状态变更方法（`POST/PUT/PATCH/DELETE`）必须在
  `X-CSRF-Token` 请求头中携带该令牌；服务端用 `hmac.compare_digest`
  与**当前会话内**的令牌做恒定时间比较。
- 判定结果可区分：
  - 令牌缺失或为空 → `csrf_token_missing`（403）；
  - 令牌非空但与会话不匹配（伪造、过期、**拿别人会话的令牌错用**）
    → `csrf_token_invalid`（403）。
- 安全方法（`GET/HEAD/OPTIONS`）不校验；依赖链顺序为
  “会话认证 → CSRF → 权限”，所以无会话时先返回 `not_authenticated`。
- 另叠加 Cookie 的 `SameSite=Strict` 属性作为纵深防御。

## 6. 统一错误码（拒绝原因可解释、可断言）

| HTTP | error.code | 触发情形 |
|------|------------|----------|
| 401 | `not_authenticated` | 无会话 Cookie / 会话不存在 |
| 401 | `invalid_credentials` | 用户名或密码错误（不区分用户是否存在） |
| 423 | `account_locked` | 该（账户, 来源IP）失败达到阈值且在锁定期内 |
| 401 | `session_expired` | 超过空闲超时或绝对上限 |
| 401 | `session_revoked` | 会话被登出/管理员/属主主动撤销 |
| 401 | `session_invalidated_by_password_change` | 密码已变更，旧会话密码版本过期 |
| 403 | `forbidden` | 从未拥有所需权限（默认拒绝） |
| 403 | `permission_revoked` | 登录时拥有、之后被在线撤销 |
| 403 | `csrf_token_missing` | 写请求缺少 CSRF 令牌 |
| 403 | `csrf_token_invalid` | CSRF 令牌与当前会话不匹配 |
| 404 | `not_found` | 目标资源（如待撤销会话）不存在 |

所有拒绝响应体统一为：

```json
{"error": {"code": "<稳定错误码>", "message": "<判定依据说明>"}}
```

## 7. 验证方法

### 7.1 自动化测试

```bash
uv run pytest
```

覆盖的并发与边界场景（共 29 个用例，分布于 `tests/`）：

- `test_auth.py`：用户不存在与密码错误不可区分；阈值锁定且判因可区分；
  账户 × 来源 IP 维度隔离；空闲过期/滑动续期/绝对上限（可控时钟）；
  锁定解除时刻确定可复现；登出撤销；**20 线程并发失败不可绕过阈值**。
- `test_session_password.py`：同账户 3 个并发会话独立撤销；
  10 个独立会话并发访问互不干扰；改密后当前会话与其它并发会话统一失效且
  判因为 `session_invalidated_by_password_change`；改密需旧密码与 CSRF；
  非属主无权限不能撤销他人会话。
- `test_rbac.py`：匿名/无权限默认拒绝且判因不同；在线撤销后同一会话得到
  `permission_revoked`；在线授予/加角色后后续请求立即放行；管理员撤销他人会话。
- `test_csrf.py`：缺失/空令牌、伪造令牌、**A 的 sid + B 的 csrf 跨会话错用**、
  安全方法豁免、无会话优先判未认证。
- `test_http_concurrency.py`：HTTP 层 12 线程并发登录计数稳定；
  撤销一个会话后并发请求分别稳定得到 `session_revoked` 与 200；
  6 会话并发使用后并发自撤、后续判因一致。

测试日志通过标准 `logging` 输出关键输入与判定依据，例如：

```
INFO tests.auth failure #5 (threshold) -> {'error': {'code': 'invalid_credentials', ...}}
INFO tests.auth post-threshold correct password -> 423 {'error': {'code': 'account_locked', ...}}
INFO tests.http_conc http concurrent bad logins total=12 invalid=5 locked=7 codes=[...]
```

### 7.2 手工 curl 验证

```bash
uv run uvicorn app.main:app --port 8000 &
# 登录并保存 Cookie（-c），CSRF 令牌在 csrf_token Cookie 中
curl -c cj -X POST localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"bob-pass"}'
CSRF=$(grep csrf_token cj | awk '{print $7}')

# 读（有权限）
curl -s -b cj localhost:8000/api/articles
# 写但不带 CSRF -> csrf_token_missing
curl -s -b cj -X POST localhost:8000/api/articles -H 'Content-Type: application/json' -d '{"title":"x"}'
# 带 CSRF 但 bob 无 article:write -> forbidden
curl -s -b cj -X POST localhost:8000/api/articles \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" -d '{"title":"x"}'
```

## 8. 代码结构

```
app/
  errors.py     # 稳定错误码与 AppError
  models.py     # User / Session / FailureCounter 数据模型
  security.py   # PBKDF2 密码哈希、随机盐/令牌（纯函数）
  store.py      # RLock 保护的线程安全内存存储
  auth.py       # 登录/锁定/续期/改密/登出（认证核心）
  rbac.py       # 角色与权限解析、授权判定、在线变更
  csrf.py       # 会话绑定 CSRF 校验
  deps.py       # FastAPI 依赖：require_session / enforce_csrf / require_permission
  container.py  # 装配与种子用户/角色
  routes.py     # HTTP 路由
  main.py       # 应用工厂、统一异常处理
tests/          # 认证/会话/RBAC/CSRF/并发 测试
```

## 9. 设计说明与局限

- 存储为单进程内存实现，旨在**本地可验证**；生产环境应替换为带事务/原子操作
  （CAS/Lua/行锁）的共享存储，并在会话 Cookie 上增加 `Secure`。
- 失败计数当前未做周期性垃圾回收（演示规模下无影响）。
- CSRF 方案适合同源前端 + 不透明会话 Cookie；若跨域提供 API，应改用
  令牌绑定的自定义请求头 + CORS 白名单等更强方案。
