# Site combined 一阶逻辑表达式汇总

## 生成模板说明

- 顺序跳步/越序模板：`RequiredBefore(A_required,A_target) ∧ ¬Before(s,A_required,A_target)`
- 重复调用模板：`CountInSession(s,A) ≥ n`
- 参数一致性模板：`ParameterFlowContext(...) ∧ ParameterAppearsOrDerived(...) ∧ ¬ParameterConsistentWithContext(...)`
- 组合风险模板：`SequenceRisk(s) ∧ ParameterRisk(s)`

## 1. 帖子编辑接口对象级越权（BOLA）- 归属上下文切换

- FOL ID: `FOL-C1-S1`
- 场景: 帖子编辑与发布接口的参数一致性破坏与越权尝试
- 类型: `BOLA` / 风险等级: `high`
- 攻击场景概述: 攻击者通过固定对象ID并切换空间ID的方式探测编辑接口的越权漏洞，参数逻辑异常清晰。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /post/post/edit
- 参数上下文 API: GET /space/space
- 参数完整链路: cguid 应稳定且与 id 的归属一致 -> GET /space/spaces -> GET /space/space -> GET /space/space/about -> POST /post/post/post -> POST /post/post/edit -> POST /like/like/like -> POST /like/like/unlike
- 参数出现位置: id @ POST /post/post/edit [query, target_parameter]；cguid @ POST /post/post/edit [query, context_parameter]
- 参数上下文绑定: GET /space/space -> POST /post/post/edit (cguid, 同一对象)
- 参数依赖关系: bound_to_upstream_context
- 参数期望来源: upstream_context_api
- 参数风险: 目标对象ID与上下文ID不匹配或多值切换

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterFlowContext(s,{C1},{T1},{P1},"bound_to_upstream_context") ∧ ParameterAppearsOrDerived(s,{T1},{P1}) ∧ ¬ParameterConsistentWithContext(s,{C1},{T1},{P1},"upstream_context_api") → RatedParameterRisk(s,"BOLA","high","帖子编辑接口对象级越权（BOLA）- 归属上下文切换"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 2. 帖子发布接口参数注入（BOLA）- 容器归属篡改

- FOL ID: `FOL-C1-S2`
- 场景: 帖子编辑与发布接口的参数一致性破坏与越权尝试
- 类型: `BOLA` / 风险等级: `high`
- 攻击场景概述: 发布接口存在明显的请求内部参数不一致，攻击者利用此缺陷尝试跨空间发布内容。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /post/post/post
- 参数上下文 API: GET /space/spaces -> GET /space/space -> GET /space/space/about
- 参数完整链路: Query cguid 应与 Body containerGuid 一致 -> GET /space/spaces -> GET /space/space -> GET /space/space/about -> POST /post/post/post -> POST /post/post/edit -> POST /like/like/like -> POST /like/like/unlike
- 参数出现位置: cguid @ POST /post/post/post [query, target_parameter]；containerGuid @ POST /post/post/post [body, target_parameter]
- 参数上下文绑定: GET /space/space -> POST /post/post/post (cguid, stable_within_target_api)；GET /space/space/about -> POST /post/post/post (cguid, stable_within_target_api)
- 参数依赖关系: stable_within_target_api
- 参数期望来源: same_request_or_business_context
- 参数风险: Query 与 Body 参数不一致

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1},{P1,P2}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1},{P1,P2},2) → RatedParameterRisk(s,"BOLA","high","帖子发布接口参数注入（BOLA）- 容器归属篡改"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 3. 邀请接口参数 cguid 跨对象枚举

- FOL ID: `FOL-C2-S2`
- 场景: 跨租户枚举与管理接口未授权扫描
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 同一会话中 cguid 参数发生切换，且目标接口未验证用户对该对象的归属权，存在对象级越权风险。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: GET /space/membership/invite
- 参数上下文 API: GET /space/space
- 参数完整链路: cguid 应保持单一值，或仅限于用户所属空间列表。 -> GET /space/spaces -> GET /space/space -> GET /space/membership/invite -> POST /space/membership/invite -> GET /notification/list -> GET /marketplace/update -> GET /admin/module/list
- 参数出现位置: cguid @ GET /space/space [query, context_source]；cguid @ GET /space/membership/invite [query, target_parameter]
- 参数上下文绑定: GET /space/space -> GET /space/membership/invite (cguid, 同一对象)
- 参数依赖关系: bound_to_upstream_context
- 参数期望来源: upstream_context_api
- 参数风险: 参数值在会话内发生非一致性切换

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterFlowContext(s,{C1},{T1},{P1},"bound_to_upstream_context") ∧ ParameterAppearsOrDerived(s,{T1},{P1}) ∧ ¬ParameterConsistentWithContext(s,{C1},{T1},{P1},"upstream_context_api") → RatedParameterRisk(s,"BOLA","medium","邀请接口参数 cguid 跨对象枚举"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 4. 更新与管理接口高频重复调用

- FOL ID: `FOL-C2-S3`
- 场景: 跨租户枚举与管理接口未授权扫描
- 类型: `RESOURCE_CONSUMPTION` / 风险等级: `medium`
- 攻击场景概述: 短时间内对特定接口的密集重复调用，缺乏频率限制，构成资源消耗风险。
- 正常链路: GET /marketplace/update -> GET /admin/module/list
- 可能违规链路: GET /marketplace/update -> GET /marketplace/update -> GET /marketplace/update -> GET /admin/module/list -> GET /admin/module/list

活动映射:
- A1: GET /marketplace/update
- A2: GET /admin/module/list

一阶逻辑表达式:
- 表达式 1 `sequence_order`:

```text
∀s (CountInSession(s,A1) ≥ 3 ∧ StatusClassIn(s,A2,{"5xx"}) → RatedSequenceOrderRisk(s,"RESOURCE_CONSUMPTION","medium","更新与管理接口高频重复调用"))
```
  说明: 如果会话中出现跳步、越序、关键步骤缺失或敏感步骤过早出现，并且响应状态码证据支持该场景，则产生序列顺序风险评级。


## 5. edit 重复调用资源消耗风险

- FOL ID: `FOL-C3-S2`
- 场景: 用户关注与账户配置接口高频滥用及参数割裂攻击
- 类型: `RESOURCE_CONSUMPTION` / 风险等级: `medium`
- 攻击场景概述: 异常高频的页面访问行为，疑似自动化探测或资源滥用。
- 正常链路: GET /user/account/edit -> POST /user/account/edit
- 可能违规链路: GET /user/account/edit -> GET /user/account/edit -> GET /user/account/edit -> GET /user/account/change-username -> GET /user/account/change-username

活动映射:
- A1: GET /user/account/edit
- A2: POST /user/account/edit
- A3: GET /user/account/change-username

一阶逻辑表达式:
- 表达式 1 `sequence_order`:

```text
∀s (CountInSession(s,A1) ≥ 3 → RatedSequenceOrderRisk(s,"RESOURCE_CONSUMPTION","medium","edit 重复调用资源消耗风险"))
```
  说明: 如果会话中出现跳步、越序、关键步骤缺失或敏感步骤过早出现，并且响应状态码证据支持该场景，则产生序列顺序风险评级。


## 6. 关注操作目标对象不一致异常

- FOL ID: `FOL-C3-S3`
- 场景: 用户关注与账户配置接口高频滥用及参数割裂攻击
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 同会话内关注/取消关注对象 ID 不一致，暴露了自动化脚本批量操作或枚举 ID 的特征。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /user/profile/unfollow
- 参数上下文 API: POST /user/profile/follow
- 参数完整链路: POST /user/profile/follow -> POST /user/profile/unfollow -> GET /user/people -> GET /user/account/edit -> GET /user/account/edit-settings -> GET /user/account/change-username -> GET /user/account/change-email
- 参数出现位置: cguid @ POST /user/profile/follow [query, context_source]；cguid @ POST /user/profile/unfollow [query, target_parameter]
- 参数上下文绑定: POST /user/profile/follow -> POST /user/profile/unfollow (cguid, 同一对象)
- 参数依赖关系: bound_to_upstream_context
- 参数期望来源: upstream_context_api
- 参数风险: unfollow 的 cguid 与 follow 的 cguid 不一致

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterFlowContext(s,{C1},{T1},{P1},"bound_to_upstream_context") ∧ ParameterAppearsOrDerived(s,{T1},{P1}) ∧ ¬ParameterConsistentWithContext(s,{C1},{T1},{P1},"upstream_context_api") → RatedParameterRisk(s,"BOLA","medium","关注操作目标对象不一致异常"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 7. 自动化关注/取关资源消耗

- FOL ID: `FOL-C4-S1`
- 场景: 自动化用户关注/取关循环与账户功能探测
- 类型: `RESOURCE_CONSUMPTION` / 风险等级: `high`
- 攻击场景概述: 检测到针对关注/取关接口的高频逆向循环调用，结合 python-requests UA，确认为自动化资源消耗行为。
- 正常链路: GET /user/people -> POST /user/profile/follow
- 可能违规链路: GET /user/people -> POST /user/profile/follow -> POST /user/profile/unfollow -> POST /user/profile/follow -> GET /user/people -> POST /user/profile/unfollow

活动映射:
- A1: GET /user/people
- A2: POST /user/profile/follow
- A3: POST /user/profile/unfollow

一阶逻辑表达式:
- 表达式 1 `sequence_order`:

```text
∀s (CountInSession(s,A1) ≥ 2 → RatedSequenceOrderRisk(s,"RESOURCE_CONSUMPTION","high","自动化关注/取关资源消耗"))
```
  说明: 如果会话中出现跳步、越序、关键步骤缺失或敏感步骤过早出现，并且响应状态码证据支持该场景，则产生序列顺序风险评级。


## 8. 用户对象 cguid 跨上下文高频操作 (BOLA/Enumeration)

- FOL ID: `FOL-C4-S2`
- 场景: 自动化用户关注/取关循环与账户功能探测
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 检测到对关注接口的 cguid 参数进行高频、多值切换操作，疑似批量操作或枚举，违反参数上下文一致性。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /user/profile/follow -> POST /user/profile/unfollow
- 参数上下文 API: 无
- 参数完整链路: cguid 应从 GET /user/people 响应中提取，并在随后的 follow/unfollow 操作中保持稳定或逐一对应。 -> GET /user/people -> POST /user/profile/follow -> GET /user/account/change-email -> GET /user/account/edit -> GET /user/account/edit-settings -> GET /user/account/change-username -> POST /user/profile/unfollow
- 参数出现位置: cguid @ POST /user/profile/follow [query, target_parameter]；cguid @ POST /user/profile/unfollow [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: 单会话内 cguid 值不固定，呈现明显的多目标切换特征。

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1,T2},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1,T2},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /user/profile/follow","POST /user/profile/unfollow"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","用户对象 cguid 跨上下文高频操作 (BOLA/Enumeration)"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 9. dashboard 业务顺序约束绕过风险

- FOL ID: `FOL-C5-S1`
- 场景: 普通用户上下文遍历管理接口与空间对象枚举攻击
- 类型: `AUTH_BYPASS` / 风险等级: `high`
- 攻击场景概述: 普通用户上下文直接访问 /admin/module/list 管理接口，严重违反最小权限原则，构成 BFLA 风险。
- 正常链路: GET /admin/login -> GET /admin/dashboard
- 可能违规链路: GET /user/people -> GET /admin/module/list

活动映射:
- A1: GET /admin/login
- A2: GET /admin/dashboard
- A3: GET /user/people
- A4: GET /admin/module/list

一阶逻辑表达式:
- 表达式 1 `sequence_order`:

```text
∀s (Occurs(s,A3) ∧ RequiredBefore(A1,A3) ∧ ¬Before(s,A1,A3) ∧ PrecheckFailedOrMissing(s,A1,{"401","403"}) → RatedSequenceOrderRisk(s,"AUTH_BYPASS","high","dashboard 业务顺序约束绕过风险"))
```
  说明: 如果会话中出现跳步、越序、关键步骤缺失或敏感步骤过早出现，并且响应状态码证据支持该场景，则产生序列顺序风险评级。


## 10. 空间管理接口对象 ID 枚举与批量访问

- FOL ID: `FOL-C5-S2`
- 场景: 普通用户上下文遍历管理接口与空间对象枚举攻击
- 类型: `BOLA` / 风险等级: `high`
- 攻击场景概述: 攻击者通过修改 cguid 参数遍历访问多个空间的管理接口，典型的 BOLA 对象级越权攻击模式。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: GET /space/manage/security -> GET /space/manage
- 参数上下文 API: 无
- 参数完整链路: cguid 参数应来源于 GET /space/spaces 返回的用户有权管理的空间列表 -> GET /space/spaces -> GET /user/people -> GET /space/manage/security -> GET /space/space -> GET /admin/module/list -> GET /user/account/edit -> GET /space/manage -> GET /user/account/change-username -> GET /marketplace/purchase -> GET /notification/list
- 参数出现位置: cguid @ GET /space/manage/security [query, target_parameter]；cguid @ GET /space/manage [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: 同一会话内针对不同对象 ID 的多值切换访问

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1,T2},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1,T2},{P1},2) → RatedParameterRisk(s,"BOLA","high","空间管理接口对象 ID 枚举与批量访问"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 11. 用户设置接口高频探测与资源消耗

- FOL ID: `FOL-C6-S1`
- 场景: 异常高频设置探测与关注对象枚举
- 类型: `RESOURCE_CONSUMPTION` / 风险等级: `high`
- 攻击场景概述: 自动化脚本对用户设置接口进行高频撞击，存在资源消耗风险，建议增加频控规则。
- 正常链路: GET /user/account/edit -> GET /user/account/change-email
- 可能违规链路: GET /user/account/change-email -> GET /user/account/change-email -> GET /user/account/change-email -> ... (Repeated 35 times)

活动映射:
- A1: GET /user/account/edit
- A2: GET /user/account/change-email
- A3: ... (Repeated 35 times)

一阶逻辑表达式:
- 表达式 1 `sequence_order`:

```text
∀s (CountInSession(s,A2) ≥ 3 → RatedSequenceOrderRisk(s,"RESOURCE_CONSUMPTION","high","用户设置接口高频探测与资源消耗"))
```
  说明: 如果会话中出现跳步、越序、关键步骤缺失或敏感步骤过早出现，并且响应状态码证据支持该场景，则产生序列顺序风险评级。


## 12. 关注/取关操作对象不一致性越权

- FOL ID: `FOL-C6-S2`
- 场景: 异常高频设置探测与关注对象枚举
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 关注与取关操作针对了不同的用户 ID，显示出攻击者可能在尝试批量操作或枚举，建议增加参数一致性校验。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /user/profile/unfollow -> POST /user/profile/follow
- 参数上下文 API: 无
- 参数完整链路: follow(cguid=A) -> unfollow(cguid=A) -> GET /user/account/edit -> GET /user/account/edit-settings -> GET /user/account/change-email -> GET /user/account/change-username -> GET /user/people -> POST /user/profile/follow -> POST /user/profile/unfollow
- 参数出现位置: cguid @ POST /user/profile/follow [query, target_parameter]；cguid @ POST /user/profile/unfollow [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: 参数值在逻辑关联的操作对中不匹配。

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1,T2},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1,T2},{P1},2) → RatedParameterRisk(s,"BOLA","medium","关注/取关操作对象不一致性越权"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 13. User-Agent 上下文不一致导致的对象级访问风险

- FOL ID: `FOL-C7-S1`
- 场景: 登录入口高频重放攻击
- 类型: `BOLA` / 风险等级: `high`
- 攻击场景概述: 该场景为典型的自动化脚本攻击，通过单一接口的高频重放消耗资源。尽管被服务端拦截（403），但异常行为特征显著，需建立频控规则。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: GET /user/auth/login
- 参数上下文 API: 参数在正常会话中应保持稳定或按业务逻辑变化
- 参数完整链路: 参数在正常会话中应保持稳定或按业务逻辑变化 -> GET /user/auth/login
- 参数出现位置: User-Agent @ GET /user/auth/login [header, target_parameter]；Cookie @ GET /user/auth/login [header, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: same_request_or_business_context
- 参数风险: 固定自动化脚本头部与无效/被禁 Cookie 的持续重放

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1},{P1,P2}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1},{P1,P2},2) → RatedParameterRisk(s,"BOLA","high","User-Agent 上下文不一致导致的对象级访问风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。
