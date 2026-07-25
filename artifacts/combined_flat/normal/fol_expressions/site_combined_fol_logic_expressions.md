# Site combined 一阶逻辑表达式汇总

## 生成模板说明

- 顺序跳步/越序模板：`RequiredBefore(A_required,A_target) ∧ ¬Before(s,A_required,A_target)`
- 重复调用模板：`CountInSession(s,A) ≥ n`
- 参数一致性模板：`ParameterFlowContext(...) ∧ ParameterAppearsOrDerived(...) ∧ ¬ParameterConsistentWithContext(...)`
- 组合风险模板：`SequenceRisk(s) ∧ ParameterRisk(s)`

## 1. cguid 上下文参数与业务顺序共同绕过风险

- FOL ID: `FOL-C2-S1`
- 场景: 用户账户设置与人员关注操作流程
- 类型: `RESOURCE_CONSUMPTION` / 风险等级: `medium`
- 攻击场景概述: 关注操作依赖客户端提供的 cguid 参数，且日志证据显示存在上下文缺失的潜在路径（虽然代表序列完整，但需防范跳步攻击），存在对象级越权访问风险。
- 正常链路: GET /user/people -> POST /user/profile/follow
- 可能违规链路: POST /user/profile/follow
- 参数目标 API: POST /user/profile/follow -> POST /user/profile/unfollow
- 参数上下文 API: 无
- 参数完整链路: GET /user/people (返回 cguid) -> POST /user/profile/follow (携带 cguid) -> GET /user/people -> POST /user/profile/follow -> GET /user/account/edit -> GET /user/account/edit-settings -> GET /user/account/change-username -> GET /user/account/change-email -> POST /user/profile/unfollow
- 参数出现位置: cguid @ POST /user/profile/follow [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: cguid 被篡改或来源不明

活动映射:
- A1: GET /user/people
- A2: POST /user/profile/follow

一阶逻辑表达式:
- 表达式 1 `sequence_order_and_parameter_consistency`:

```text
∀s ((Occurs(s,A2) ∧ RequiredBefore(A1,A2) ∧ ¬Before(s,A1,A2) ∧ ParameterAppearsOrDerived(s,{T1,T2},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1,T2},{P1},2) ∧ StatusClassIn(s,A2,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /user/profile/follow","POST /user/profile/unfollow"},{"2xx"})) → RatedCombinedSequenceParameterRisk(s,"RESOURCE_CONSUMPTION","medium","cguid 上下文参数与业务顺序共同绕过风险"))
```
  说明: 当顺序链被破坏，并且关键对象参数也存在来源不明、中途替换或上下文不一致时，结合响应状态码证据产生组合风险评级。


## 2. 空间详情接口 cguid 参数脱离列表上下文导致的对象级越权访问风险

- FOL ID: `FOL-C5-S1`
- 场景: 用户工作台与个人中心只读浏览流程
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 该场景针对只读业务流程中最典型的对象级越权风险：通过列表接口限定可见范围，攻击者可能绕过此限制直接访问详情接口。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: GET /space/space
- 参数上下文 API: 无
- 参数完整链路: GET /space/spaces (返回用户可见空间列表) -> GET /space/space (携带列表中的 cguid) -> GET /space/spaces -> GET /user/people -> GET /space/space -> GET /user/account/edit -> GET /user/account/change-username -> GET /notification/list
- 参数出现位置: cguid @ GET /space/space [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: query 参数 cguid 被替换为非当前用户上下文的值

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"GET /space/space"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","空间详情接口 cguid 参数脱离列表上下文导致的对象级越权访问风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 3. 发布帖子时容器ID脱离社区访问上下文导致的对象级越权风险

- FOL ID: `FOL-8-1`
- 场景: 社区浏览与内容发布及互动流程
- 类型: `BOLA` / 风险等级: `high`
- 攻击场景概述: 发布接口依赖客户端提供的 containerGuid 确定目标对象，且存在明确的社区访问前置步骤，破坏该参数绑定关系即可实现跨社区越权发布。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /post/post/post
- 参数上下文 API: GET /space/space
- 参数完整链路: GET /space/space?cguid=xxx -> POST /post/post/post (body.containerGuid=xxx) -> GET /space/spaces -> GET /space/space -> GET /space/space/about -> POST /post/post/post -> POST /like/like/like -> POST /like/like/unlike
- 参数出现位置: cguid @ GET /space/space [query, context_source]；containerGuid @ POST /post/post/post [body, target_parameter]
- 参数上下文绑定: GET /space/space -> POST /post/post/post (cguid, bound_to_upstream_context)
- 参数依赖关系: bound_to_upstream_context
- 参数期望来源: upstream_context_api
- 参数风险: containerGuid 值与上游 cguid 不一致或来源不明

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterFlowContext(s,{C1},{T1},{P1},"bound_to_upstream_context") ∧ ParameterAppearsOrDerived(s,{T1},{P1}) ∧ ¬ParameterConsistentWithContext(s,{C1},{T1},{P1},"upstream_context_api") ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /post/post/post"},{"2xx"}) → RatedParameterRisk(s,"BOLA","high","发布帖子时容器ID脱离社区访问上下文导致的对象级越权风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 4. 点赞操作中内容ID脱离创建或浏览上下文导致的对象级越权风险

- FOL ID: `FOL-8-2`
- 场景: 社区浏览与内容发布及互动流程
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 点赞接口接收客户端传入的 contentId，攻击者可能通过枚举该ID对不可见帖子进行越权互动。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /like/like/like
- 参数上下文 API: 无
- 参数完整链路: POST /post/post/post (创建帖子) -> POST /like/like/like (点赞刚创建的帖子) -> GET /space/spaces -> GET /space/space -> GET /space/space/about -> POST /post/post/post -> POST /like/like/like -> POST /like/like/unlike
- 参数出现位置: contentId @ POST /like/like/like [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: contentId 来源不明或与上游上下文不符

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /like/like/like"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","点赞操作中内容ID脱离创建或浏览上下文导致的对象级越权风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 5. 空间GUID脱离列表上下文导致的对象级访问风险

- FOL ID: `FOL-9-1`
- 场景: 用户多视图信息浏览模式
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 参数 cguid 从列表页流向详情页，若服务端未校验其是否属于当前用户上下文，则攻击者可枚举或替换 cguid 越权访问其他空间。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: GET /space/space
- 参数上下文 API: 无
- 参数完整链路: GET /space/spaces (提供可用空间列表) -> GET /space/space (使用列表中的 cguid 访问详情) -> GET /space/spaces -> GET /user/people -> GET /space/space -> GET /user/account/edit -> GET /notification/list
- 参数出现位置: cguid @ GET /space/space [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: cguid 被替换为非当前用户列表中的值或枚举值

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"GET /space/space"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","空间GUID脱离列表上下文导致的对象级访问风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 6. 用户关注接口 cguid 参数篡改导致的对象级越权风险

- FOL ID: `FOL-C12-S1`
- 场景: 用户社交互动与内容管理流程
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 关注接口的目标对象 ID (cguid) 缺乏与前置浏览/查看上下文的强制校验，攻击者可枚举 ID 实现越权关注。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /user/profile/follow
- 参数上下文 API: GET /user/profile -> GET /user/profile/about
- 参数完整链路: GET /user/profile?cguid=xxx -> POST /user/profile/follow?cguid=xxx -> GET /space/spaces -> GET /space/space -> GET /user/profile/about -> GET /user/account/edit -> GET /user/account/edit-settings -> GET /user/account/change-username -> GET /user/account/change-email -> GET /user/profile -> GET /notification/list -> POST /comment/comment/show -> POST /like/like/unlike -> POST /user/profile/unfollow
- 参数出现位置: cguid @ GET /user/profile [query, context_source]；cguid @ POST /user/profile/follow [query, target_parameter]
- 参数上下文绑定: GET /user/profile -> POST /user/profile/follow (cguid, 同一对象)
- 参数依赖关系: bound_to_upstream_context
- 参数期望来源: upstream_context_api
- 参数风险: cguid 参数值不属于当前会话上下文（如未出现在搜索结果、资料详情中）

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterFlowContext(s,{C1,C2},{T1},{P1},"bound_to_upstream_context") ∧ ParameterAppearsOrDerived(s,{T1},{P1}) ∧ ¬ParameterConsistentWithContext(s,{C1,C2},{T1},{P1},"upstream_context_api") ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /user/profile/follow"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","用户关注接口 cguid 参数篡改导致的对象级越权风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 7. 帖子发布 containerGuid 篡改导致的越权发布风险

- FOL ID: `FOL-C12-S2`
- 场景: 用户社交互动与内容管理流程
- 类型: `BOLA` / 风险等级: `high`
- 攻击场景概述: 发帖接口的 containerGuid 参数决定内容发布空间，若仅依赖客户端传值而未校验用户对该空间的写权限，将导致越权发布。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /post/post/post
- 参数上下文 API: 无
- 参数完整链路: GET /space/space?cguid=xxx -> POST /post/post/post(containerGuid=xxx) -> GET /space/spaces -> GET /space/space -> GET /user/profile/about -> GET /user/account/edit -> GET /user/account/edit-settings -> GET /user/account/change-username -> GET /user/account/change-email -> GET /user/profile -> GET /notification/list -> POST /comment/comment/show -> POST /like/like/unlike -> POST /user/profile/unfollow
- 参数出现位置: cguid @ GET /space/space [query, context_source]；containerGuid @ POST /post/post/post [body, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: containerGuid 参数值被篡改，不属于用户当前访问的空间上下文

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /post/post/post"},{"2xx"}) → RatedParameterRisk(s,"BOLA","high","帖子发布 containerGuid 篡改导致的越权发布风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 8. 空间ID参数脱离列表上下文导致的对象级访问风险

- FOL ID: `FOL-C13-S1`
- 场景: 用户仪表盘自动刷新与数据轮询业务
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 核心参数 cguid 在业务中起对象定位作用，若未校验其与上游列表接口的归属关系，攻击者可枚举越权访问其他空间。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: GET /space/space
- 参数上下文 API: 无
- 参数完整链路: GET /space/spaces -> GET /space/space -> GET /space/spaces -> GET /user/people -> GET /space/space -> GET /admin/module/list -> GET /marketplace/purchase -> GET /notification/list
- 参数出现位置: cguid @ GET /space/space [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: 客户端替换或枚举 cguid 参数

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"GET /space/space"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","空间ID参数脱离列表上下文导致的对象级访问风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 9. list 业务顺序约束绕过风险

- FOL ID: `FOL-C13-S2`
- 场景: 用户仪表盘自动刷新与数据轮询业务
- 类型: `AUTH_BYPASS` / 风险等级: `high`
- 攻击场景概述: 普通用户业务流中直接包含 /admin/module/list 调用，违背最小权限原则，若接口无强角色校验则构成功能级越权。
- 正常链路: GET /space/spaces -> GET /user/people -> GET /space/space -> GET /notification/list
- 可能违规链路: GET /space/spaces -> GET /admin/module/list

活动映射:
- A1: GET /space/spaces
- A2: GET /user/people
- A3: GET /space/space
- A4: GET /notification/list
- A5: GET /admin/module/list

一阶逻辑表达式:
- 表达式 1 `sequence_order`:

```text
∀s (Occurs(s,A1) ∧ RequiredBefore(A2,A1) ∧ ¬Before(s,A2,A1) ∧ StatusClassIn(s,A1,{"2xx"}) → RatedSequenceOrderRisk(s,"AUTH_BYPASS","high","list 业务顺序约束绕过风险"))
```
  说明: 如果会话中出现跳步、越序、关键步骤缺失或敏感步骤过早出现，并且响应状态码证据支持该场景，则产生序列顺序风险评级。


## 10. page 上下文不一致导致的对象级访问风险

- FOL ID: `FOL-C14-S1`
- 场景: 用户账户设置页面导航流程
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 该场景针对用户列表查询接口的分页与查询参数，存在被滥用进行数据遍历或资源消耗的可能性，属于 API 风险检测中的常见低风险场景。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: GET /user/people
- 参数上下文 API: GET /user/account/edit
- 参数完整链路: GET /user/account/edit -> GET /user/people -> GET /user/account/edit-settings -> GET /user/account/change-username -> GET /user/account/change-email
- 参数出现位置: page @ GET /user/people [query, target_parameter]；keyword @ GET /user/people [query, target_parameter]；Content-Type @ GET /user/account/edit [header, context_source]；Content-Type @ GET /user/people [header, target_parameter]；content-type @ GET /user/account/edit [header, context_source]；content-type @ GET /user/people [header, target_parameter]；User-Agent @ GET /user/account/edit [header, context_source]；User-Agent @ GET /user/people [header, target_parameter]
- 参数上下文绑定: GET /user/account/edit -> GET /user/people (Content-Type, stable_within_target_api)；GET /user/account/edit -> GET /user/people (content-type, stable_within_target_api)；GET /user/account/edit -> GET /user/people (User-Agent, stable_within_target_api)；GET /user/account/edit -> GET /user/people (Content-Type, stable_within_target_api)；GET /user/account/edit -> GET /user/people (content-type, stable_within_target_api)
- 参数依赖关系: stable_within_target_api
- 参数期望来源: same_request_or_business_context
- 参数风险: page 参数过大或 keyword 包含高成本查询字符

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1},{P1,P2,P3,P4,P5}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1},{P1,P2,P3,P4,P5},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"GET /user/people"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","page 上下文不一致导致的对象级访问风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 11. 关注/取关接口中 cguid 参数脱离上下文导致的对象级越权风险

- FOL ID: `FOL-C15-S1`
- 场景: 用户社交关系管理流程（查看设置-浏览用户-关注/取关）
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 关注/取关操作依赖客户端提交的 cguid 标识，存在对象级越权风险（BOLA）。日志中存在同一会话内 follow 与 unfollow 操作指向不同 cguid 的现象，暗示参数具有高度可构造性。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /user/profile/follow -> POST /user/profile/unfollow
- 参数上下文 API: 无
- 参数完整链路: GET /user/people (返回用户列表及cguid) -> POST /user/profile/follow (使用列表中的cguid) -> GET /user/account/edit -> GET /user/account/edit-settings -> GET /user/people -> POST /user/profile/follow -> POST /user/profile/unfollow
- 参数出现位置: cguid @ POST /user/profile/follow [query, target_parameter]；cguid @ POST /user/profile/unfollow [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: cguid 参数值被篡改、枚举或不匹配前置列表上下文

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1,T2},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1,T2},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /user/profile/follow","POST /user/profile/unfollow"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","关注/取关接口中 cguid 参数脱离上下文导致的对象级越权风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 12. 空间访问越权风险 (Space GUID BOLA)

- FOL ID: `FOL-18-1`
- 场景: 用户空间浏览与账户设置查看流程
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 该场景检测用户是否通过篡改 cguid 参数访问未授权空间，属于典型的对象级越权风险。由于日志缺少状态码，需后续结合响应结果验证。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: GET /space/space
- 参数上下文 API: 无
- 参数完整链路: GET /space/spaces (返回用户可见空间列表) -> GET /space/space (使用列表中的 cguid 访问详情) -> GET /space/spaces -> GET /space/space -> GET /user/people -> GET /user/account/edit -> GET /user/account/change-username -> GET /notification/list
- 参数出现位置: cguid @ GET /space/space [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: cguid 参数值被篡改或枚举

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"GET /space/space"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","空间访问越权风险 (Space GUID BOLA)"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 13. 空间详情访问UUID脱离列表上下文导致的对象级越权风险

- FOL ID: `FOL-C19-S1`
- 场景: 用户浏览空间列表与通知后进入特定空间并访问账户设置页面
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 存在典型的列表-详情参数流动模式，攻击者可绕过列表过滤直接请求详情接口，存在对象级越权风险，且详情接口写操作潜力较高。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: GET /space/space
- 参数上下文 API: 无
- 参数完整链路: GET /space/spaces -> GET /space/space -> GET /space/spaces -> GET /user/people -> GET /notification/list -> GET /space/space -> GET /user/account/edit -> GET /user/account/change-username
- 参数出现位置: cguid @ GET /space/space [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: cguid 参数被替换为非上下文来源的枚举值或跨对象 ID

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"GET /space/space"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","空间详情访问UUID脱离列表上下文导致的对象级越权风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 14. 空间管理安全设置接口的对象级越权访问风险

- FOL ID: `FOL-C20-S1`
- 场景: 空间管理与用户设置浏览流程
- 类型: `BOLA` / 风险等级: `high`
- 攻击场景概述: 安全管理接口直接使用客户端传入的对象标识 cguid 且缺乏显式权限校验证据，极易受对象级越权攻击，属于高风险场景
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: GET /space/manage/security -> GET /space/manage
- 参数上下文 API: GET /space/spaces -> GET /space/space
- 参数完整链路: GET /space/spaces -> GET /space/space?cguid=xxx -> GET /space/manage/security?cguid=xxx -> GET /user/people -> GET /space/space -> GET /space/manage -> GET /space/manage/security -> GET /user/account/edit -> GET /user/account/change-username
- 参数出现位置: cguid @ GET /space/space [query, context_source]；cguid @ GET /space/manage/security [query, target_parameter]
- 参数上下文绑定: GET /space/space -> GET /space/manage/security (cguid, 归属依赖)
- 参数依赖关系: bound_to_upstream_context
- 参数期望来源: upstream_context_api
- 参数风险: 请求目标接口的 cguid 未出现在上游上下文接口中，或直接请求目标接口

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterFlowContext(s,{C1,C2},{T1,T2},{P1},"bound_to_upstream_context") ∧ ParameterAppearsOrDerived(s,{T1,T2},{P1}) ∧ ¬ParameterConsistentWithContext(s,{C1,C2},{T1,T2},{P1},"upstream_context_api") ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"GET /space/manage/security","GET /space/manage"},{"2xx"}) → RatedParameterRisk(s,"BOLA","high","空间管理安全设置接口的对象级越权访问风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 15. 关注/取关接口对象 ID (cguid) 脱离上下文导致的 BOLA 风险

- FOL ID: `FOL-C21-S1`
- 场景: 用户搜索与社交操作自动化脚本
- 类型: `BOLA` / 风险等级: `high`
- 攻击场景概述: 自动化脚本直接传递用户 ID (cguid) 进行关注/取关操作，若服务端未校验该 ID 是否属于当前用户的合法社交范围，将导致对象级越权。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /user/profile/follow -> POST /user/profile/unfollow
- 参数上下文 API: 无
- 参数完整链路: GET /user/people (获取用户列表/关键词搜索) -> POST /user/profile/follow (传入指定的 cguid) -> GET /user/people -> POST /user/profile/follow -> POST /user/profile/unfollow -> GET /user/account/edit -> GET /user/account/change-username -> GET /user/account/change-email
- 参数出现位置: keyword @ GET /user/people [query, context_source]；cguid @ POST /user/profile/follow [query, target_parameter]；cguid @ POST /user/profile/unfollow [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: cguid 被篡改为非上下文用户 ID

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1,T2},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1,T2},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /user/profile/follow","POST /user/profile/unfollow"},{"2xx"}) → RatedParameterRisk(s,"BOLA","high","关注/取关接口对象 ID (cguid) 脱离上下文导致的 BOLA 风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 16. 高频用户搜索接口导致的资源消耗风险

- FOL ID: `FOL-C21-S2`
- 场景: 用户搜索与社交操作自动化脚本
- 类型: `RESOURCE_CONSUMPTION` / 风险等级: `medium`
- 攻击场景概述: 该聚类表现出明显的自动化爬虫特征（高频搜索+脚本 UA），虽然未直接破坏业务逻辑，但对系统资源造成压力。
- 正常链路: GET /user/people -> POST /user/profile/follow
- 可能违规链路: GET /user/people -> GET /user/people -> GET /user/people

活动映射:
- A1: GET /user/people
- A2: POST /user/profile/follow

一阶逻辑表达式:
- 表达式 1 `sequence_order`:

```text
∀s (CountInSession(s,A1) ≥ 3 → RatedSequenceOrderRisk(s,"RESOURCE_CONSUMPTION","medium","高频用户搜索接口导致的资源消耗风险"))
```
  说明: 如果会话中出现跳步、越序、关键步骤缺失或敏感步骤过早出现，并且响应状态码证据支持该场景，则产生序列顺序风险评级。


## 17. 发帖接口 containerGuid 脱离当前空间上下文导致的对象级越权

- FOL ID: `FOL-22-1`
- 场景: 用户进入空间发帖并点赞互动流程
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 发帖接口允许客户端指定容器 ID，若缺少对容器归属和权限的严格校验，攻击者可利用此缺陷向无权访问的空间注入内容。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /post/post/post
- 参数上下文 API: 无
- 参数完整链路: GET /space/space (cguid) -> POST /post/post/post (containerGuid) -> GET /space/spaces -> GET /space/space -> POST /post/post/post -> POST /like/like/like -> POST /like/like/unlike
- 参数出现位置: cguid @ GET /space/space [query, context_source]；containerGuid @ POST /post/post/post [body, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: containerGuid 与上游 cguid 不一致

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /post/post/post"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","发帖接口 containerGuid 脱离当前空间上下文导致的对象级越权"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 18. 点赞接口 contentId 缺少对象归属校验导致的越权操作

- FOL ID: `FOL-22-2`
- 场景: 用户进入空间发帖并点赞互动流程
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 点赞接口若未校验内容对象与当前空间上下文的归属关系，攻击者可利用此缺陷对任意可见内容进行操作，破坏空间隔离。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /like/like/like -> POST /like/like/unlike
- 参数上下文 API: GET /space/space
- 参数完整链路: GET /space/space (提供空间上下文) -> POST /like/like/like (操作该空间内的内容) -> GET /space/spaces -> GET /space/space -> POST /post/post/post -> POST /like/like/like -> POST /like/like/unlike
- 参数出现位置: cguid @ GET /space/space [query, context_source]；contentId @ POST /like/like/like [query, target_parameter]
- 参数上下文绑定: GET /space/space -> POST /like/like/like (contentId, bound_to_upstream_context)；GET /space/space -> POST /like/like/unlike (contentId, bound_to_upstream_context)
- 参数依赖关系: bound_to_upstream_context
- 参数期望来源: upstream_context_api
- 参数风险: contentId 来源不明或跨空间

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterFlowContext(s,{C1},{T1,T2},{P1},"bound_to_upstream_context") ∧ ParameterAppearsOrDerived(s,{T1,T2},{P1}) ∧ ¬ParameterConsistentWithContext(s,{C1},{T1,T2},{P1},"upstream_context_api") ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /like/like/like","POST /like/like/unlike"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","点赞接口 contentId 缺少对象归属校验导致的越权操作"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 19. 空间对象 cguid 越权访问风险

- FOL ID: `FOL-C23-S1`
- 场景: 用户空间浏览与个人设置查看流程
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 访问空间详情接口 GET /space/space 时使用了高熵的 UUID 参数 cguid，且该参数应当受限于上游列表接口的权限范围，存在典型的对象级越权风险。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: GET /space/space
- 参数上下文 API: 无
- 参数完整链路: GET /space/spaces -> cguid (from response) -> GET /space/space?cguid=<id> -> GET /space/spaces -> GET /space/space -> GET /user/account/edit -> GET /user/account/change-username -> GET /notification/list -> GET /user/people
- 参数出现位置: cguid @ GET /space/space [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: 请求中的 cguid 未在上游列表上下文中出现或来源不明

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"GET /space/space"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","空间对象 cguid 越权访问风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 20. 空间详情ID脱离列表上下文导致的对象级访问风险

- FOL ID: `FOL-24-1`
- 场景: 用户浏览空间列表与详情并访问账户设置
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 详情接口 cguid 参数存在典型的 BOLA 风险，应校验其是否属于上游列表可见集合
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: GET /space/space
- 参数上下文 API: 无
- 参数完整链路: GET /space/spaces -> GET /space/space?cguid=xxx -> GET /user/people -> GET /space/spaces -> GET /space/space -> GET /user/account/edit
- 参数出现位置: cguid @ GET /space/space [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: cguid 被替换或枚举，导致跨对象访问

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"GET /space/space"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","空间详情ID脱离列表上下文导致的对象级访问风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 21. 直接访问空间安全管理接口可能绕过权限检查

- FOL ID: `FOL-25-scenario-1`
- 场景: 用户浏览空间详情并进入安全管理页面的只读探索流程
- 类型: `AUTH_BYPASS` / 风险等级: `medium`
- 攻击场景概述: 管理类接口通常需要较高权限，直接访问详情接口存在越权风险，但需状态码确认
- 正常链路: GET /space/spaces -> GET /space/space -> GET /space/manage -> GET /space/manage/security
- 可能违规链路: GET /space/manage/security

活动映射:
- A1: GET /space/spaces
- A2: GET /space/space
- A3: GET /space/manage
- A4: GET /space/manage/security

一阶逻辑表达式:
- 表达式 1 `sequence_order`:

```text
∀s (Occurs(s,A4) ∧ RequiredBefore(A3,A4) ∧ ¬Before(s,A3,A4) ∧ StatusClassIn(s,A4,{"2xx"}) → RatedSequenceOrderRisk(s,"AUTH_BYPASS","medium","直接访问空间安全管理接口可能绕过权限检查"))
```
  说明: 如果会话中出现跳步、越序、关键步骤缺失或敏感步骤过早出现，并且响应状态码证据支持该场景，则产生序列顺序风险评级。


## 22. 空间管理接口 cguid 参数可能被枚举或替换导致对象级越权

- FOL ID: `FOL-25-scenario-2`
- 场景: 用户浏览空间详情并进入安全管理页面的只读探索流程
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 管理接口参数 cguid 直接来源于上一级详情页，存在被篡改导致越权访问其他空间管理页的风险
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: GET /space/manage/security
- 参数上下文 API: GET /space/space
- 参数完整链路: GET /space/space (cguid) -> GET /space/manage/security (cguid) -> GET /user/account/edit -> GET /user/account/change-username -> GET /user/people -> GET /space/spaces -> GET /space/space -> GET /notification/list -> GET /space/manage -> GET /space/manage/security
- 参数出现位置: cguid @ GET /space/space [query, context_source]；cguid @ GET /space/manage/security [query, target_parameter]
- 参数上下文绑定: GET /space/space -> GET /space/manage/security (cguid, 同一对象)
- 参数依赖关系: bound_to_upstream_context
- 参数期望来源: upstream_context_api
- 参数风险: cguid 参数被替换为非授权对象 ID

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterFlowContext(s,{C1},{T1},{P1},"bound_to_upstream_context") ∧ ParameterAppearsOrDerived(s,{T1},{P1}) ∧ ¬ParameterConsistentWithContext(s,{C1},{T1},{P1},"upstream_context_api") ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"GET /space/manage/security"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","空间管理接口 cguid 参数可能被枚举或替换导致对象级越权"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 23. cguid 上下文参数与业务顺序共同绕过风险

- FOL ID: `FOL-26-S1`
- 场景: 空间详情查看后进入管理安全设置页面流程
- 类型: `BFLA` / 风险等级: `high`
- 攻击场景概述: 管理接口直接暴露 cguid 参数且可能缺少权限归属校验，攻击者可绕过详情页直接探测或篡改 cguid 访问未授权空间配置，风险等级高
- 正常链路: GET /space/space -> GET /space/manage -> GET /space/manage/security
- 可能违规链路: GET /space/manage/security
- 参数目标 API: GET /space/manage/security -> GET /space/manage
- 参数上下文 API: GET /space/space
- 参数完整链路: GET /space/space?cguid=X -> GET /space/manage?cguid=X -> GET /space/manage/security?cguid=X -> GET /space/space -> GET /space/manage -> GET /space/manage/security -> GET /space/spaces
- 参数出现位置: cguid @ GET /space/space [query, context_source]；cguid @ GET /space/manage [query, target_parameter]；cguid @ GET /space/manage/security [query, target_parameter]
- 参数上下文绑定: GET /space/space -> GET /space/manage/security (cguid, 同一对象)
- 参数依赖关系: bound_to_upstream_context
- 参数期望来源: upstream_context_api
- 参数风险: cguid 参数值与前置详情页不一致，或直接携带未知 cguid 访问管理接口

活动映射:
- A1: GET /space/space
- A2: GET /space/manage
- A3: GET /space/manage/security

一阶逻辑表达式:
- 表达式 1 `sequence_order_and_parameter_consistency`:

```text
∀s ((Occurs(s,A3) ∧ RequiredBefore(A1,A3) ∧ ¬Before(s,A1,A3) ∧ ParameterFlowContext(s,{C1},{T1,T2},{P1},"bound_to_upstream_context") ∧ ParameterAppearsOrDerived(s,{T1,T2},{P1}) ∧ ¬ParameterConsistentWithContext(s,{C1},{T1,T2},{P1},"upstream_context_api") ∧ StatusClassIn(s,A3,{"2xx"}) ∧ ApiStatusClassIn(s,{"GET /space/manage/security","GET /space/manage"},{"2xx"})) → RatedCombinedSequenceParameterRisk(s,"BFLA","high","cguid 上下文参数与业务顺序共同绕过风险"))
```
  说明: 当顺序链被破坏，并且关键对象参数也存在来源不明、中途替换或上下文不一致时，结合响应状态码证据产生组合风险评级。


## 24. 空间管理接口的对象级越权访问风险

- FOL ID: `FOL-28-scenario-1`
- 场景: 空间搜索与管理及内容发布流程
- 类型: `BOLA` / 风险等级: `high`
- 攻击场景概述: 管理类接口直接使用客户端提供的 cguid 且缺乏可见的权限校验上下文，存在极高的对象级越权风险。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: GET /space/manage -> GET /space/manage/default/advanced
- 参数上下文 API: 无
- 参数完整链路: GET /space/spaces (获取空间列表) -> GET /space/space (查看特定空间详情) -> GET /space/manage (进入管理) -> GET /space/spaces -> GET /space/browse/search-json -> GET /space/space -> GET /space/manage -> GET /space/manage/default/advanced -> POST /post/post/post -> POST /post/post/edit
- 参数出现位置: cguid @ GET /space/manage [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: cguid 被替换为非上下文来源的任意 UUID

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1,T2},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1,T2},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"GET /space/manage","GET /space/manage/default/advanced"},{"2xx"}) → RatedParameterRisk(s,"BOLA","high","空间管理接口的对象级越权访问风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 25. 帖子编辑接口的对象级越权风险

- FOL ID: `FOL-28-scenario-2`
- 场景: 空间搜索与管理及内容发布流程
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 编辑接口参数 ID 来自客户端且未在上下文中明确绑定来源，存在通过 ID 枚举进行越权编辑的风险。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /post/post/edit
- 参数上下文 API: 无
- 参数完整链路: POST /post/post/post (创建帖子) -> POST /post/post/edit (编辑刚创建的帖子) -> GET /space/spaces -> GET /space/browse/search-json -> GET /space/space -> GET /space/manage -> GET /space/manage/default/advanced -> POST /post/post/post -> POST /post/post/edit
- 参数出现位置: id @ POST /post/post/edit [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: id 参数被替换为非当前上下文生成的值

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /post/post/edit"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","帖子编辑接口的对象级越权风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 26. 关注接口中用户对象 ID(cguid) 可能被篡改导致的越权访问

- FOL ID: `FOL-C30-S1`
- 场景: 用户账户设置浏览后关注特定用户流程
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 关注接口直接接收用户标识 cguid，且逻辑上依赖搜索结果，若缺乏校验则存在对象级越权风险。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /user/profile/follow
- 参数上下文 API: 无
- 参数完整链路: GET /user/people (获取用户列表/上下文) -> POST /user/profile/follow (提交选定的 cguid) -> GET /user/account/edit -> GET /user/account/edit-settings -> GET /user/account/change-username -> GET /user/people -> POST /user/profile/follow
- 参数出现位置: cguid @ POST /user/profile/follow [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: cguid 参数被替换、枚举或不属于搜索结果集

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /user/profile/follow"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","关注接口中用户对象 ID(cguid) 可能被篡改导致的越权访问"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 27. cguid 上下文参数与业务顺序共同绕过风险

- FOL ID: `FOL-C31-S1`
- 场景: 用户账户管理与社交互动流程
- 类型: `BOPLA` / 风险等级: `medium`
- 攻击场景概述: 关注/取关接口POST请求携带对象标识cguid，且前置存在用户列表接口，存在典型的BOLA参数脱离上下文风险；因缺乏状态码证据，暂定为中风险。
- 正常链路: GET /user/people -> POST /user/profile/follow
- 可能违规链路: POST /user/profile/follow
- 参数目标 API: POST /user/profile/follow -> POST /user/profile/unfollow
- 参数上下文 API: 无
- 参数完整链路: GET /user/people (返回用户列表及cguid) -> POST /user/profile/follow (提交选定的cguid) -> GET /user/people -> POST /user/profile/follow -> GET /user/account/edit -> POST /user/profile/unfollow -> GET /user/account/change-username -> GET /user/account/change-email
- 参数出现位置: cguid @ POST /user/profile/follow [query, target_parameter]；cguid @ POST /user/profile/unfollow [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: 请求体或查询参数中的cguid与上游列表上下文不一致或完全缺失上游上下文。

活动映射:
- A1: GET /user/people
- A2: POST /user/profile/follow

一阶逻辑表达式:
- 表达式 1 `sequence_order_and_parameter_consistency`:

```text
∀s ((Occurs(s,A2) ∧ RequiredBefore(A1,A2) ∧ ¬Before(s,A1,A2) ∧ ParameterAppearsOrDerived(s,{T1,T2},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1,T2},{P1},2) ∧ StatusClassIn(s,A2,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /user/profile/follow","POST /user/profile/unfollow"},{"2xx"})) → RatedCombinedSequenceParameterRisk(s,"BOPLA","medium","cguid 上下文参数与业务顺序共同绕过风险"))
```
  说明: 当顺序链被破坏，并且关键对象参数也存在来源不明、中途替换或上下文不一致时，结合响应状态码证据产生组合风险评级。


## 28. 社交关注操作中 cguid 参数可能被篡改导致的对象级越权风险

- FOL ID: `FOL-32-1`
- 场景: 用户个人配置浏览与社交关注操作
- 类型: `BOLA` / 风险等级: `high`
- 攻击场景概述: 关注/取关接口直接使用客户端提交的 UUID 作为操作对象，且前置存在明显的搜索/列表接口作为上下文，存在典型的对象级越权风险。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /user/profile/follow -> POST /user/profile/unfollow
- 参数上下文 API: 无
- 参数完整链路: GET /user/people (获取可选用户列表及ID) -> POST /user/profile/follow (提交选定的cguid) -> GET /user/account/edit -> GET /user/account/edit-settings -> GET /user/people -> POST /user/profile/follow -> POST /user/profile/unfollow -> GET /user/account/change-email -> GET /user/account/change-username
- 参数出现位置: cguid @ POST /user/profile/follow [query, target_parameter]；cguid @ POST /user/profile/unfollow [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: cguid 参数值与前置搜索/列表接口返回的用户ID集合不一致

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1,T2},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1,T2},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /user/profile/follow","POST /user/profile/unfollow"},{"2xx"}) → RatedParameterRisk(s,"BOLA","high","社交关注操作中 cguid 参数可能被篡改导致的对象级越权风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 29. 关注/取关操作中cguid参数脱离用户列表上下文导致的对象级越权风险

- FOL ID: `FOL-33-1`
- 场景: 用户设置浏览与关注操作流程
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 关注/取关接口依赖客户端提供的 cguid 参数，且该参数通常来源于前置的用户列表页面。若接口未校验参数归属，攻击者可通过篡改 ID 对非预期用户执行操作。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /user/profile/follow -> POST /user/profile/unfollow
- 参数上下文 API: 无
- 参数完整链路: GET /user/people (获取列表) -> POST /user/profile/follow (对列表中某项操作) -> GET /user/account/edit -> GET /user/people -> GET /user/account/edit-settings -> GET /user/account/change-username -> GET /user/account/change-email -> POST /user/profile/follow -> POST /user/profile/unfollow
- 参数出现位置: cguid @ POST /user/profile/follow [query, target_parameter]；cguid @ POST /user/profile/unfollow [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: cguid 参数被替换、枚举或来源不明。

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1,T2},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1,T2},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /user/profile/follow","POST /user/profile/unfollow"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","关注/取关操作中cguid参数脱离用户列表上下文导致的对象级越权风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 30. 跳过用户列表页面直接执行关注操作的顺序风险

- FOL ID: `FOL-33-2`
- 场景: 用户设置浏览与关注操作流程
- 类型: `RESOURCE_CONSUMPTION` / 风险等级: `low`
- 攻击场景概述: 虽然直接调用关注接口可能属于业务允许的行为，但大量缺失前置浏览的请求可能暗示自动化枚举攻击。
- 正常链路: GET /user/people -> POST /user/profile/follow
- 可能违规链路: POST /user/profile/follow

活动映射:
- A1: GET /user/people
- A2: POST /user/profile/follow

一阶逻辑表达式:
- 表达式 1 `sequence_order`:

```text
∀s (Occurs(s,A2) ∧ RequiredBefore(A1,A2) ∧ ¬Before(s,A1,A2) → RatedSequenceOrderRisk(s,"RESOURCE_CONSUMPTION","low","跳过用户列表页面直接执行关注操作的顺序风险"))
```
  说明: 如果会话中出现跳步、越序、关键步骤缺失或敏感步骤过早出现，并且响应状态码证据支持该场景，则产生序列顺序风险评级。


## 31. cguid 上下文参数与业务顺序共同绕过风险

- FOL ID: `FOL-C34-S1`
- 场景: 用户搜索与社交关注管理
- 类型: `RESOURCE_CONSUMPTION` / 风险等级: `medium`
- 攻击场景概述: 攻击者可绕过用户搜索上下文，直接通过篡改 cguid 参数对任意用户发起关注或取关请求，存在对象级越权风险。
- 正常链路: GET /user/people -> POST /user/profile/follow
- 可能违规链路: POST /user/profile/follow
- 参数目标 API: POST /user/profile/follow -> POST /user/profile/unfollow
- 参数上下文 API: 无
- 参数完整链路: GET /user/people (获取用户列表/ID) -> POST /user/profile/follow (提交指定ID) -> GET /user/people -> POST /user/profile/follow -> POST /user/profile/unfollow
- 参数出现位置: cguid @ POST /user/profile/follow [query, target_parameter]；cguid @ POST /user/profile/unfollow [query, target_parameter]；keyword @ GET /user/people [query, context_source]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: cguid 参数值来源于枚举、外部输入或与上下文用户列表不一致

活动映射:
- A1: GET /user/people
- A2: POST /user/profile/follow

一阶逻辑表达式:
- 表达式 1 `sequence_order_and_parameter_consistency`:

```text
∀s ((Occurs(s,A2) ∧ RequiredBefore(A1,A2) ∧ ¬Before(s,A1,A2) ∧ ParameterAppearsOrDerived(s,{T1,T2},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1,T2},{P1},2) ∧ StatusClassIn(s,A2,{"2xx"}) ∧ PrecheckFailedOrMissing(s,A1,{"401","403"}) ∧ ApiStatusClassIn(s,{"POST /user/profile/follow","POST /user/profile/unfollow"},{"2xx"})) → RatedCombinedSequenceParameterRisk(s,"RESOURCE_CONSUMPTION","medium","cguid 上下文参数与业务顺序共同绕过风险"))
```
  说明: 当顺序链被破坏，并且关键对象参数也存在来源不明、中途替换或上下文不一致时，结合响应状态码证据产生组合风险评级。


## 32. 关注/取关操作中用户对象ID (cguid) 脱离列表上下文导致的对象级访问风险

- FOL ID: `FOL-35-scenario-1`
- 场景: 用户中心浏览与社交关注/取关操作流程
- 类型: `BOLA` / 风险等级: `medium`
- 攻击场景概述: 关注与取关接口依赖客户端提交的 cguid，存在跳过列表上下文直接访问对象的风险，属于典型的对象级越权 (BOLA) 场景。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /user/profile/follow -> POST /user/profile/unfollow
- 参数上下文 API: 无
- 参数完整链路: GET /user/people (response contains user list with cguid) -> POST /user/profile/follow?cguid=... -> GET /user/account/edit -> GET /user/people -> POST /user/profile/follow -> POST /user/profile/unfollow -> GET /user/account/change-email
- 参数出现位置: cguid @ POST /user/profile/follow [query, target_parameter]；cguid @ POST /user/profile/unfollow [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: cguid 参数值不匹配上游上下文或缺失上游上下文

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterAppearsOrDerived(s,{T1,T2},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1,T2},{P1},2) ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /user/profile/follow","POST /user/profile/unfollow"},{"2xx"}) → RatedParameterRisk(s,"BOLA","medium","关注/取关操作中用户对象ID (cguid) 脱离列表上下文导致的对象级访问风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。


## 33. cguid 上下文参数与业务顺序共同绕过风险

- FOL ID: `FOL-C36-S1`
- 场景: 用户个人中心访问与关注操作
- 类型: `RESOURCE_CONSUMPTION` / 风险等级: `medium`
- 攻击场景概述: 关注接口依赖客户端提供的对象ID（cguid），且正常流程中存在明显的上下文来源（用户列表页）。攻击者可能通过跳过列表页直接操作目标对象，实现越权关注。
- 正常链路: GET /user/people -> POST /user/profile/follow
- 可能违规链路: POST /user/profile/follow
- 参数目标 API: POST /user/profile/follow -> POST /user/profile/unfollow
- 参数上下文 API: 无
- 参数完整链路: GET /user/people (获取用户列表) -> POST /user/profile/follow (提交选定的 cguid) -> GET /user/people -> POST /user/profile/follow -> POST /user/profile/unfollow -> GET /user/account/edit -> GET /user/account/edit-settings -> GET /user/account/change-username -> GET /user/account/change-email
- 参数出现位置: cguid @ POST /user/profile/follow [query, target_parameter]；cguid @ POST /user/profile/unfollow [query, target_parameter]
- 参数上下文绑定: 无
- 参数依赖关系: stable_within_target_api
- 参数期望来源: target_api_observed_values
- 参数风险: cguid 参数值被替换、枚举或不属于当前用户可见范围

活动映射:
- A1: GET /user/people
- A2: POST /user/profile/follow

一阶逻辑表达式:
- 表达式 1 `sequence_order_and_parameter_consistency`:

```text
∀s ((Occurs(s,A2) ∧ RequiredBefore(A1,A2) ∧ ¬Before(s,A1,A2) ∧ ParameterAppearsOrDerived(s,{T1,T2},{P1}) ∧ DistinctTargetParameterValuesAtLeast(s,{T1,T2},{P1},2) ∧ StatusClassIn(s,A2,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /user/profile/follow","POST /user/profile/unfollow"},{"2xx"})) → RatedCombinedSequenceParameterRisk(s,"RESOURCE_CONSUMPTION","medium","cguid 上下文参数与业务顺序共同绕过风险"))
```
  说明: 当顺序链被破坏，并且关键对象参数也存在来源不明、中途替换或上下文不一致时，结合响应状态码证据产生组合风险评级。


## 34. 邀请接口 cguid 参数脱离前置上下文导致的对象级越权风险

- FOL ID: `FOL-38-1`
- 场景: 空间成员邀请流程（含参数上下文不一致特征）
- 类型: `BOLA` / 风险等级: `high`
- 攻击场景概述: 该场景捕捉到典型的对象级越权特征：用户在具备合法上下文（邀请页面）的情况下，向不同的目标对象（空间 ID）提交写操作。
- 正常链路: 无
- 可能违规链路: 无
- 参数目标 API: POST /space/membership/invite
- 参数上下文 API: GET /space/membership/invite
- 参数完整链路: GET /space/space?cguid=X -> GET /space/membership/invite?cguid=X -> POST /space/membership/invite?cguid=X -> GET /space/spaces -> GET /space/space -> GET /notification/list -> GET /space/membership/invite -> POST /space/membership/invite
- 参数出现位置: cguid @ GET /space/membership/invite [query, context_source]；cguid @ POST /space/membership/invite [query, target_parameter]
- 参数上下文绑定: GET /space/membership/invite -> POST /space/membership/invite (cguid, 同一对象)
- 参数依赖关系: bound_to_upstream_context
- 参数期望来源: upstream_context_api
- 参数风险: cguid 参数在 POST 请求中被替换为非当前上下文加载的值

活动映射:
- 无

一阶逻辑表达式:
- 表达式 1 `parameter_consistency`:

```text
∀s (ParameterFlowContext(s,{C1},{T1},{P1},"bound_to_upstream_context") ∧ ParameterAppearsOrDerived(s,{T1},{P1}) ∧ ¬ParameterConsistentWithContext(s,{C1},{T1},{P1},"upstream_context_api") ∧ StatusClassIn(s,A_risk,{"2xx"}) ∧ ApiStatusClassIn(s,{"POST /space/membership/invite"},{"2xx"}) → RatedParameterRisk(s,"BOLA","high","邀请接口 cguid 参数脱离前置上下文导致的对象级越权风险"))
```
  说明: 如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。
