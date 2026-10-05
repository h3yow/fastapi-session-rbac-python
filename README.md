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
  旧会话此后一律得到 `401 session_password_changed`。
- 会话判定顺序：缺失 → `session_missing`；不认识的 id → `session_unknown`；
  被撤销 → 按原因分为 `session_revoked`（登出/被踢）与
  `session_password_changed`（改密整批失效）；过期 → `session_expired`。
  四种失效原因彼此可区分，且与权限类拒绝（403）不会混淆。

## 权限模型（RBAC）

- 角色 → 权限映射由 `PolicyEngine` 持有，默认：`reader: reports:read`；
  `editor: +reports:write`；`admin: +admin:users, admin:policy, admin:sessions`。
- 默认拒绝：受保护端点无会话一律 401；有会话但无角色 → `403 forbidden_role`；
  角色本就不具备该权限 → `403 forbidden_permission`；该权限在运行时被收回
  → `403 permission_revoked`（三种拒绝原因可区分）。
- 热更新：`PolicyEngine.update(...)` 原子替换策略并递增版本号，后续请求立即生效，
  无需重启；拒绝详情中会标注判定所用的策略版本。
- 匿名接口 `GET /` 行为保持兼容（返回 `{"Hello": "World"}`）。

## 运行时权限管理（不停机）

- `GET /admin/policy`（需 `admin:policy` 权限）：查看当前策略快照与版本号。
- `POST /admin/policy/grant` / `POST /admin/policy/revoke`
  （需 `admin:policy` 权限 + CSRF）：对单个角色授予/收回单个权限，
  原子生效并递增策略版本，后续请求立即按新策略判定。
- 这两个管理端点本身同样默认拒绝：匿名 401、无权限角色 403、缺少 CSRF 头
  `403 csrf_missing`。
- 拒绝原因区分基于「启动时策略快照」：角色在启动时拥有、运行时被收回的权限
  报 `permission_revoked`；启动时就没有的权限报 `forbidden_permission`。

## 会话管理（查看与定点撤销）

- `GET /sessions`（需会话）：列出当前账号全部有效会话，含 `session_id`、
  已建立时长 `age_seconds`、剩余时长 `expires_in_seconds`、是否当前会话
  `is_current`。
- `DELETE /sessions/{sid}`（需会话 + CSRF）：撤销自己账号的某一个会话，
  只影响被点名的会话；他人会话 id 一律按不存在处理（404，不泄露存在性）。
- `GET /admin/users/{username}/sessions`、`DELETE /admin/users/{username}/sessions/{sid}`
  （需 `admin:sessions` 权限，后者需 CSRF）：管理员对他人会话做同样操作。
- 撤销结果确定且可复现：目标不存在 → `404 session_not_found`；
  已被撤销 → `409 session_already_revoked`；成功 → 200。
- 并发语义：撤销与请求竞争时，请求要么在撤销生效前正常完成（200），
  要么在撤销后一律被拒（`401 session_revoked`）；撤销确认后该会话
  不可能再继续使用，同账号其他会话不受影响。

## CSRF 防护规则

- 所有状态变更端点（`/logout`、`/refresh`、`/change-password`、`POST /reports`、
  `/admin/policy/grant`、`/admin/policy/revoke`、`DELETE /sessions/{sid}`、
  `DELETE /admin/users/{username}/sessions/{sid}`）要求 `X-CSRF-Token` 头。
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
| `tests/test_admin_policy.py` | 运行时授权/收回立即生效、管理端点默认拒绝与 CSRF、收回与从未授予的区分 |
| `tests/test_sessions.py` | 会话列举、定点撤销（本人/管理员）、404/409 可复现结果、四类失效原因区分 |
| `tests/test_concurrency.py` | 并发锁定不越阈值、并发登录会话独立、改密并发失效、撤销与请求竞争、并发重复撤销、并发 CSRF 误用 |

测试通过 `fake_clock` 夹具注入确定性时钟验证过期/续期/解锁边界；
日志（`log_cli` 开启）打印每个用例的关键输入与判定依据。

## 兼容性说明

- 原有匿名接口（`GET /`、`POST /login`）行为不变。
- 既有错误码中，`session_invalid` 被细分为 `session_unknown` /
  `session_revoked` / `session_password_changed`（改密整批失效归入
  `session_password_changed`，行为本身不变）；调用方若按旧码判断需相应调整。
- 权限拒绝细分为 `forbidden_permission`（从未授予）与
  `permission_revoked`（运行时收回），均仍为 403。
