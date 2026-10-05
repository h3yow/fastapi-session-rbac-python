# FastAPI Session Auth + RBAC Demo

本地可验证的会话认证与访问控制服务：内存态、线程安全、可用 `pytest` 全量验证。

## 运行与验证

```bash
uv sync                 # 安装依赖
uv run pytest           # 运行全部测试（含并发用例，日志打印关键输入与判定依据）
uv run python main.py   # 启动服务（预置 alice/reader 与 admin/admin 两个账号）
```

预置账号：`alice/alice-password`（reader）、`admin/admin-password`（admin）。

## 认证流程

- `POST /login`（匿名）：校验成功后签发会话，通过 `HttpOnly` Cookie（`session_id`）
  与响应体返回 `session_id` 与 `csrf_token`。失败统一返回
  `401 invalid_credentials`——无论账号不存在还是密码错误，响应码与文案完全一致，
  且对不存在账号走相同的哈希校验路径，不暴露账号是否存在。
- `POST /logout`（需会话 + CSRF）：仅撤销当前会话；同账号其他会话不受影响，
  各自可独立撤销。
- `POST /refresh`（需会话 + CSRF）：仅在过期前 `refresh_window_seconds`（默认 600s）
  内允许续期；续期延长 `session_ttl_seconds`（默认 1800s）并轮换 CSRF 令牌。
  过早续期返回 401，保证最大空闲时间有确定上界。
- `POST /change-password`（需会话 + CSRF）：校验旧密码后修改密码，
  用户密码代际（`password_generation`）+1 并撤销该账号全部会话；
  旧会话此后一律得到 `401 session_invalid`。
- 会话判定顺序：缺失（`missing`）→ 不认识（`unknown`）→ 密码已变更
  （`password_changed`）→ 被显式撤销（`kicked`）→ 过期（`expired`）。
  原因彼此可区分，细分值见下文「会话失效原因」。

## 权限模型（RBAC）

- 角色 → 权限映射由 `PolicyEngine` 持有，默认：`reader: reports:read`；
  `editor: +reports:write`；`admin: +admin:users`，admin 另含运行期管理权限
  `admin:roles:write`、`admin:sessions:write`（默认仅 admin 拥有）。
- 默认拒绝：受保护端点无会话一律 401；有会话但无角色 → `403 forbidden_role`；
  角色不具备该权限 → `403 forbidden_permission`（拒绝原因可区分）。
- 热更新：`PolicyEngine.update(...)` / `update_role(...)` 在锁内原子替换策略并
  递增版本号，后续请求立即生效，无需重启；拒绝详情中会标注判定所用的策略版本。
- 两类权限拒绝可分开判断（响应体 `error.reason`）：
  - `never_granted`：该角色在任何历史策略版本中都没有过这项权限；
  - `revoked_at_runtime`：该角色曾经拥有、但被运行期调整收回了。
  顶层 `code` 仍是 `forbidden_permission`，旧调用方不受影响。
- 匿名接口 `GET /` 行为保持兼容（返回 `{"Hello": "World"}`）。

## 运行期管理能力（对外 HTTP，无需停机）

所有管理端点都走原有「会话 + 权限 + CSRF」链：默认拒绝、按权限放行、
写操作必须带 `X-CSRF-Token`；匿名接口不受影响。

### 角色权限调整（需要 `admin:roles:write`）

- `GET /admin/roles/{role}`：查看某角色当前权限与策略版本；未知角色
  → `404 role_not_found`。
- `PUT /admin/roles/{role}/permissions`（CSRF）：请求体
  `{"permissions": ["reports:read", ...]}`，**原子替换该一个角色**的权限集，
  其他角色不变，返回新的 `policy_version`；改完对之后的请求立即生效。
  未知角色 → `404 role_not_found`；缺少 CSRF → `403 csrf_missing`；
  非管理员 → `403 forbidden_permission`。

```bash
# 收回 editor 的写权限（立即生效）
curl -X PUT http://127.0.0.1:8000/admin/roles/editor/permissions \
  -H "Cookie: session_id=<admin sid>" -H "X-CSRF-Token: <admin csrf>" \
  -H "Content-Type: application/json" -d '{"permissions": ["reports:read"]}'
# 此后 editor 再写：403 forbidden_permission, reason=revoked_at_runtime
```

### 会话查看与定点撤销

| 端点 | 权限 | 说明 |
| --- | --- | --- |
| `GET /me/sessions` | 已登录 | 列出本账号全部会话，每个会话含 `session_id`、`created_at`、`expires_at`、`remaining_seconds` 与 `status`（`active`/`kicked`/`expired`/`password_changed`） |
| `DELETE /me/sessions/{id}` | 已登录 + CSRF | 踢掉本账号指定的单个会话 |
| `GET /admin/users/{username}/sessions` | `admin:sessions:write` | 管理员查看他人会话；未知用户 → 404 |
| `DELETE /admin/sessions/{id}` | `admin:sessions:write` + CSRF | 管理员定点踢掉任意会话 |

定点撤销只让被点名的会话失效，同账号其他会话不受影响。撤销结果确定、可复现：

- 撤销成功 → `200 {"revoked": true, "result": "revoked"}`（只有一个调用者能得到）；
- 目标 id 不存在 / 不属于自己（自管端点）→ `404 session_not_found`；
- 目标存在但早已失效（被踢/过期/改密）→ `409 session_already_invalid`，
  重复调用结果一致。

### 并发撤销的线性化保证

会话的读取是在 `SessionStore` 单把锁内取得的快照，「查状态」与「置撤销位」
在同一临界区完成。因此一次正在处理的请求与一次撤销竞争时结果确定：

- 请求在撤销落锁前完成 → 正常返回；
- 请求在撤销落锁后判定 → 一律拒绝（`reason=kicked`）；

不会出现「撤销返回成功、该会话却还能继续用」的情况；对同一 id 并发撤销时
恰好一个返回 `revoked`，其余返回 `already_revoked`。

## 会话失效原因（彼此可区分）

会话类失败的顶层 `code` 保持向后兼容，细分原因放在响应体 `error.reason`：

| 场景 | HTTP | `code` | `reason` |
| --- | --- | --- | --- |
| 没有会话 Cookie | 401 | `session_missing` | `missing` |
| 服务端不认识的 id | 401 | `session_invalid` | `unknown` |
| 被人为踢掉（登出/自踢/管理员踢） | 401 | `session_invalid` | `kicked` |
| 改密码导致整批失效（既有行为不变） | 401 | `session_invalid` | `password_changed` |
| 超过有效期 | 401 | `session_expired` | `expired` |
| 权限不足（与上面不是同一类） | 403 | `forbidden_permission` / `forbidden_role` | `never_granted` / `revoked_at_runtime` |

判定顺序：缺失 → 不认识 → 密码代际已变更（改密）→ 已被显式撤销（踢）→
已过期，各原因不会互相混淆。改密依旧令该账号现有会话全部失效，单独归类为
`password_changed`。

## CSRF 防护规则

- 所有状态变更端点（`/logout`、`/refresh`、`/change-password`、`POST /reports`、
  `PUT /admin/roles/...`、`DELETE /me/sessions/...`、`DELETE /admin/sessions/...`）
  要求 `X-CSRF-Token` 头。
- 令牌按会话签发、与会话绑定：缺失 → `403 csrf_missing`；
  过期或不属于当前会话 → `403 csrf_invalid`（与权限拒绝 403 通过 `code` 区分）。
- 令牌随登录/续期轮换，有效期 `csrf_ttl_seconds`（不超过会话 TTL）。

## 登录滥用控制（锁定策略）

- 维度：按 `(账号, 来源IP)` 计数，互不影响。
- 计数：滑动窗口 `login_failure_window_seconds`（默认 300s）内失败达到
  `login_max_failures`（默认 5）即锁定 `login_lockout_seconds`（默认 300s）。
- 并发一致性：锁定检查与失败计数在同一把锁内完成，并发突发无法越过阈值；
  锁定期间即使密码正确也返回 `401 account_locked`（与 `invalid_credentials` 可区分）。
- 解除条件确定且可复现：锁定时长到期自动解除；登录成功立即清零该维度的失败计数。

## 测试与验证方法

| 文件 | 覆盖 |
| --- | --- |
| `tests/test_auth.py` | 失败不可区分性、锁定阈值/解除、过期与续期窗口、改密失效、独立撤销 |
| `tests/test_rbac.py` | 默认拒绝、拒绝原因区分、权限授予/撤销热生效、匿名接口兼容 |
| `tests/test_csrf.py` | 令牌缺失/伪造/跨会话/过期，及与会话过期的原因区分 |
| `tests/test_concurrency.py` | 并发锁定不越阈值、并发登录会话独立、改密并发失效、并发 CSRF 误用 |
| `tests/test_admin_roles.py` | 角色权限端点默认拒绝/CSRF、单角色热授予与收回、`never_granted` 与 `revoked_at_runtime` 区分、未知角色 404 |
| `tests/test_sessions_admin.py` | 自己/管理员查看会话（时间与状态）、定点撤销只影响目标、越权与跨账号、404/409 可复现结果 |
| `tests/test_invalidation_reasons.py` | unknown/kicked/password_changed/expired/missing 与权限拒绝的可区分性 |
| `tests/test_concurrent_revoke.py` | 撤销与请求竞争的线性化、同 id 并发撤销唯一胜出、撤销后一律拒绝、HTTP 层可复现结果 |

测试通过 `fake_clock` 夹具注入确定性时钟验证过期/续期/解锁边界；
日志（`log_cli` 开启）打印每个用例的关键输入（账号、目标会话、权限集等）
与最终判定（状态码、`code`/`reason`、策略版本、撤销结果），便于排查。
