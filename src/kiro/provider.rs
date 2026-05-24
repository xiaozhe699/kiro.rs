//! Kiro API Provider
//!
//! 核心组件，负责与 Kiro API 通信
//! 支持流式和非流式请求
//! 支持多凭据故障转移和重试
//! 支持按凭据级 endpoint 切换不同 Kiro API 端点

use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use crate::http_client::{ProxyConfig, build_client};
use crate::kiro::endpoint::{KiroEndpoint, RequestContext};
use crate::kiro::machine_id;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::token_manager::{CallContext, MultiTokenManager, RateLimitReason};
use crate::model::config::TlsBackend;
use parking_lot::Mutex;

/// 每个凭据的最大重试次数
const MAX_RETRIES_PER_CREDENTIAL: usize = 3;

/// 总重试次数硬上限（避免无限重试）
const MAX_TOTAL_RETRIES: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamRateLimitKind {
    Normal,
    Suspicious,
}

impl UpstreamRateLimitKind {
    fn as_log_label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Suspicious => "suspicious",
        }
    }

    fn reason(self) -> RateLimitReason {
        match self {
            Self::Normal => RateLimitReason::Normal,
            Self::Suspicious => RateLimitReason::Suspicious,
        }
    }
}

/// 上游账号均处于 429 限流时返回的结构化错误
#[derive(Debug)]
pub struct RateLimitError {
    message: String,
    retry_after_seconds: Option<u64>,
}

impl RateLimitError {
    pub fn new(message: impl Into<String>, retry_after_seconds: Option<u64>) -> Self {
        Self {
            message: message.into(),
            retry_after_seconds,
        }
    }

    pub fn retry_after_seconds(&self) -> Option<u64> {
        self.retry_after_seconds
    }
}

impl fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RateLimitError {}

/// Kiro API Provider
///
/// 核心组件，负责与 Kiro API 通信
/// 支持多凭据故障转移和重试机制
/// 按凭据 `endpoint` 字段选择 [`KiroEndpoint`] 实现
pub struct KiroProvider {
    token_manager: Arc<MultiTokenManager>,
    /// 全局代理配置（用于凭据无自定义代理时的回退）
    global_proxy: Option<ProxyConfig>,
    /// Client 缓存：key = effective proxy config, value = reqwest::Client
    /// 不同代理配置的凭据使用不同的 Client，共享相同代理的凭据复用 Client
    client_cache: Mutex<HashMap<Option<ProxyConfig>, Client>>,
    /// TLS 后端配置
    tls_backend: TlsBackend,
    /// 端点实现注册表（key: endpoint 名称）
    endpoints: HashMap<String, Arc<dyn KiroEndpoint>>,
    /// 默认端点名称（凭据未指定 endpoint 时使用）
    default_endpoint: String,
}

impl KiroProvider {
    /// 创建带代理配置和端点注册表的 KiroProvider 实例
    ///
    /// # Arguments
    /// * `token_manager` - 多凭据 Token 管理器
    /// * `proxy` - 全局代理配置
    /// * `endpoints` - 端点名 → 实现的注册表（至少包含 `default_endpoint` 对应条目）
    /// * `default_endpoint` - 凭据未显式指定 endpoint 时使用的名称
    pub fn with_proxy(
        token_manager: Arc<MultiTokenManager>,
        proxy: Option<ProxyConfig>,
        endpoints: HashMap<String, Arc<dyn KiroEndpoint>>,
        default_endpoint: String,
    ) -> Self {
        assert!(
            endpoints.contains_key(&default_endpoint),
            "默认端点 {} 未在 endpoints 注册表中",
            default_endpoint
        );
        let tls_backend = token_manager.config().tls_backend;
        // 预热：构建全局代理对应的 Client
        let initial_client = build_client(proxy.as_ref(), 720, tls_backend)
            .expect("创建 HTTP 客户端失败");
        let mut cache = HashMap::new();
        cache.insert(proxy.clone(), initial_client);

        Self {
            token_manager,
            global_proxy: proxy,
            client_cache: Mutex::new(cache),
            tls_backend,
            endpoints,
            default_endpoint,
        }
    }

    /// 根据凭据的代理配置获取（或创建并缓存）对应的 reqwest::Client
    fn client_for(&self, credentials: &KiroCredentials) -> anyhow::Result<Client> {
        let effective = credentials.effective_proxy(self.global_proxy.as_ref());
        let mut cache = self.client_cache.lock();
        if let Some(client) = cache.get(&effective) {
            return Ok(client.clone());
        }
        let client = build_client(effective.as_ref(), 720, self.tls_backend)?;
        cache.insert(effective, client.clone());
        Ok(client)
    }

    /// 根据凭据选择 endpoint 实现
    fn endpoint_for(
        &self,
        credentials: &KiroCredentials,
    ) -> anyhow::Result<Arc<dyn KiroEndpoint>> {
        let name = credentials
            .endpoint
            .as_deref()
            .unwrap_or(&self.default_endpoint);
        self.endpoints
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("未知端点: {}", name))
    }

    fn rate_limit_retries_per_credential(&self) -> usize {
        self.token_manager
            .config()
            .rate_limit_retries_per_credential
            .try_into()
            .unwrap_or(2)
    }

    fn rate_limit_cooldown(&self) -> Duration {
        Duration::from_secs(self.token_manager.config().rate_limit_cooldown_seconds.max(1))
    }

    fn suspicious_rate_limit_retries_per_credential(&self) -> usize {
        self.token_manager
            .config()
            .suspicious_rate_limit_retries_per_credential
            .try_into()
            .unwrap_or(0)
    }

    fn suspicious_rate_limit_cooldown(&self) -> Duration {
        Duration::from_secs(
            self.token_manager
                .config()
                .suspicious_rate_limit_cooldown_seconds
                .max(1),
        )
    }

    fn rate_limit_max_cooled_credentials_per_request(&self) -> usize {
        self.token_manager
            .config()
            .rate_limit_max_cooled_credentials_per_request
            .max(1)
            .try_into()
            .unwrap_or(2)
    }

    fn retries_for_rate_limit_kind(&self, kind: UpstreamRateLimitKind) -> usize {
        match kind {
            UpstreamRateLimitKind::Normal => self.rate_limit_retries_per_credential(),
            UpstreamRateLimitKind::Suspicious => {
                self.suspicious_rate_limit_retries_per_credential()
            }
        }
    }

    fn cooldown_for_rate_limit_kind(&self, kind: UpstreamRateLimitKind) -> Duration {
        match kind {
            UpstreamRateLimitKind::Normal => self.rate_limit_cooldown(),
            UpstreamRateLimitKind::Suspicious => self.suspicious_rate_limit_cooldown(),
        }
    }

    fn classify_rate_limit_body(body: &str) -> UpstreamRateLimitKind {
        let normalized = body.to_ascii_lowercase();
        if normalized.contains("suspicious activity")
            || normalized.contains("temporary limits")
            || normalized.contains("while we investigate")
        {
            UpstreamRateLimitKind::Suspicious
        } else {
            UpstreamRateLimitKind::Normal
        }
    }

    fn rate_limit_error(
        &self,
        model: Option<&str>,
        fallback_retry_after_seconds: Option<u64>,
        message: &'static str,
    ) -> anyhow::Error {
        let retry_after = self
            .token_manager
            .rate_limit_retry_after_seconds(model)
            .or(fallback_retry_after_seconds);
        RateLimitError::new(message, retry_after).into()
    }

    fn all_credentials_rate_limit_error(
        &self,
        model: Option<&str>,
        fallback_retry_after_seconds: Option<u64>,
    ) -> anyhow::Error {
        self.rate_limit_error(
            model,
            fallback_retry_after_seconds,
            "All available upstream credentials are currently rate limited.",
        )
    }

    fn per_request_rate_limit_error(
        &self,
        model: Option<&str>,
        fallback_retry_after_seconds: Option<u64>,
    ) -> anyhow::Error {
        self.rate_limit_error(
            model,
            fallback_retry_after_seconds,
            "Upstream rate limit protection is active for this request. Please retry later.",
        )
    }

    async fn send_mcp_once(
        &self,
        ctx: &CallContext,
        endpoint: &Arc<dyn KiroEndpoint>,
        request_body: &str,
    ) -> anyhow::Result<reqwest::Response> {
        let config = self.token_manager.config();
        let machine_id = machine_id::generate_from_credentials(&ctx.credentials, config);
        let rctx = RequestContext {
            credentials: &ctx.credentials,
            token: &ctx.token,
            machine_id: &machine_id,
            config,
        };

        let url = endpoint.mcp_url(&rctx);
        let body = endpoint.transform_mcp_body(request_body, &rctx);
        let base = self
            .client_for(&ctx.credentials)?
            .post(&url)
            .body(body)
            .header("content-type", "application/json")
            .header("Connection", "close");

        Ok(endpoint.decorate_mcp(base, &rctx).send().await?)
    }

    async fn send_api_once(
        &self,
        ctx: &CallContext,
        endpoint: &Arc<dyn KiroEndpoint>,
        request_body: &str,
    ) -> anyhow::Result<reqwest::Response> {
        let config = self.token_manager.config();
        let machine_id = machine_id::generate_from_credentials(&ctx.credentials, config);
        let rctx = RequestContext {
            credentials: &ctx.credentials,
            token: &ctx.token,
            machine_id: &machine_id,
            config,
        };

        let url = endpoint.api_url(&rctx);
        let body = endpoint.transform_api_body(request_body, &rctx);
        let base = self
            .client_for(&ctx.credentials)?
            .post(&url)
            .body(body)
            .header("content-type", "application/json")
            .header("Connection", "close");

        Ok(endpoint.decorate_api(base, &rctx).send().await?)
    }

    /// 发送非流式 API 请求
    ///
    /// 支持多凭据故障转移（见 [`Self::call_api_with_retry`]）
    pub async fn call_api(&self, request_body: &str) -> anyhow::Result<reqwest::Response> {
        self.call_api_with_retry(request_body, false).await
    }

    /// 发送流式 API 请求
    pub async fn call_api_stream(&self, request_body: &str) -> anyhow::Result<reqwest::Response> {
        self.call_api_with_retry(request_body, true).await
    }

    /// 发送 MCP API 请求（WebSearch 等工具调用）
    pub async fn call_mcp(&self, request_body: &str) -> anyhow::Result<reqwest::Response> {
        self.call_mcp_with_retry(request_body).await
    }

    /// 内部方法：带重试逻辑的 MCP API 调用
    async fn call_mcp_with_retry(&self, request_body: &str) -> anyhow::Result<reqwest::Response> {
        let total_credentials = self.token_manager.total_count();
        let max_retries = (total_credentials * MAX_RETRIES_PER_CREDENTIAL).min(MAX_TOTAL_RETRIES);
        let rate_limit_retries = self.rate_limit_retries_per_credential();
        let suspicious_rate_limit_retries = self.suspicious_rate_limit_retries_per_credential();
        let max_credential_rate_limit_retries =
            rate_limit_retries.max(suspicious_rate_limit_retries);
        let rate_limit_cooldown = self.rate_limit_cooldown();
        let max_cooled_credentials = self.rate_limit_max_cooled_credentials_per_request();
        let mut cooled_credentials = 0usize;
        let mut last_error: Option<anyhow::Error> = None;
        let mut force_refreshed: HashSet<u64> = HashSet::new();

        'outer: for attempt in 0..max_retries {
            // MCP 调用（WebSearch 等工具）不涉及模型选择，无需按模型过滤凭据
            let ctx = match self.token_manager.acquire_context(None).await {
                Ok(c) => c,
                Err(e) => {
                    if self.token_manager.rate_limit_retry_after_seconds(None).is_some() {
                        return Err(self.all_credentials_rate_limit_error(
                            None,
                            Some(rate_limit_cooldown.as_secs()),
                        ));
                    }
                    last_error = Some(e);
                    continue;
                }
            };

            let endpoint = match self.endpoint_for(&ctx.credentials) {
                Ok(e) => e,
                Err(e) => {
                    last_error = Some(e);
                    // endpoint 解析失败：记为失败，换下一张凭据
                    self.token_manager.report_failure(ctx.id);
                    continue;
                }
            };

            for credential_attempt in 0..=max_credential_rate_limit_retries {
                let response = match self.send_mcp_once(&ctx, &endpoint, request_body).await {
                    Ok(resp) => resp,
                    Err(e) => {
                        tracing::warn!(
                            "MCP 请求发送失败（尝试 {}/{}）: {}",
                            attempt + 1,
                            max_retries,
                            e
                        );
                        last_error = Some(e);
                        if attempt + 1 < max_retries {
                            sleep(Self::retry_delay(attempt)).await;
                        }
                        continue 'outer;
                    }
                };

                let status = response.status();

                // 成功响应
                if status.is_success() {
                    self.token_manager.report_success(ctx.id);
                    return Ok(response);
                }

                // 失败响应
                let body = response.text().await.unwrap_or_default();

                if status.as_u16() == 429 {
                    let rate_limit_kind = Self::classify_rate_limit_body(&body);
                    let retries_for_kind = self.retries_for_rate_limit_kind(rate_limit_kind);
                    let cooldown_for_kind = self.cooldown_for_rate_limit_kind(rate_limit_kind);

                    if credential_attempt < retries_for_kind {
                        tracing::warn!(
                            "MCP 请求触发 429（类型 {}，凭据 #{}，账号内重试 {}/{}）: {}",
                            rate_limit_kind.as_log_label(),
                            ctx.id,
                            credential_attempt + 1,
                            retries_for_kind,
                            body
                        );
                        sleep(Self::retry_delay(credential_attempt)).await;
                        continue;
                    }

                    tracing::warn!(
                        "MCP 请求凭据 #{} 触发 {} 429，进入冷却 {} 秒",
                        ctx.id,
                        rate_limit_kind.as_log_label(),
                        cooldown_for_kind.as_secs()
                    );
                    cooled_credentials += 1;
                    let has_available = self
                        .token_manager
                        .report_rate_limited(ctx.id, cooldown_for_kind, rate_limit_kind.reason());
                    last_error = Some(self.all_credentials_rate_limit_error(
                        None,
                        Some(cooldown_for_kind.as_secs()),
                    ));
                    if !has_available {
                        return Err(last_error.unwrap());
                    }
                    if cooled_credentials >= max_cooled_credentials {
                        tracing::warn!(
                            "MCP 请求触发 429 熔断保护：本次请求已冷却 {} 个凭据，停止继续切换账号",
                            cooled_credentials
                        );
                        return Err(self.per_request_rate_limit_error(
                            None,
                            Some(cooldown_for_kind.as_secs()),
                        ));
                    }
                    continue 'outer;
                }

                // 402 额度用尽
                if status.as_u16() == 402 && endpoint.is_monthly_request_limit(&body) {
                    let has_available = self.token_manager.report_quota_exhausted(ctx.id);
                    if !has_available {
                        anyhow::bail!("MCP 请求失败（所有凭据已用尽）: {} {}", status, body);
                    }
                    last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                    continue 'outer;
                }

                // 400 Bad Request
                if status.as_u16() == 400 {
                    anyhow::bail!("MCP 请求失败: {} {}", status, body);
                }

                // 401/403 凭据问题
                if matches!(status.as_u16(), 401 | 403) {
                    // token 被上游失效：先尝试 force-refresh，每凭据仅一次机会
                    if endpoint.is_bearer_token_invalid(&body) && !force_refreshed.contains(&ctx.id)
                    {
                        force_refreshed.insert(ctx.id);
                        tracing::info!("凭据 #{} token 疑似被上游失效，尝试强制刷新", ctx.id);
                        if self.token_manager.force_refresh_token_for(ctx.id).await.is_ok() {
                            tracing::info!("凭据 #{} token 强制刷新成功，重试请求", ctx.id);
                            continue 'outer;
                        }
                        tracing::warn!("凭据 #{} token 强制刷新失败，计入失败", ctx.id);
                    }

                    let has_available = self.token_manager.report_failure(ctx.id);
                    if !has_available {
                        anyhow::bail!("MCP 请求失败（所有凭据已用尽）: {} {}", status, body);
                    }
                    last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                    continue 'outer;
                }

                // 瞬态错误
                if status.as_u16() == 408 || status.is_server_error() {
                    tracing::warn!(
                        "MCP 请求失败（上游瞬态错误，尝试 {}/{}）: {} {}",
                        attempt + 1,
                        max_retries,
                        status,
                        body
                    );
                    last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                    if attempt + 1 < max_retries {
                        sleep(Self::retry_delay(attempt)).await;
                    }
                    continue 'outer;
                }

                // 其他 4xx
                if status.is_client_error() {
                    anyhow::bail!("MCP 请求失败: {} {}", status, body);
                }

                // 兜底
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                if attempt + 1 < max_retries {
                    sleep(Self::retry_delay(attempt)).await;
                }
                continue 'outer;
            }
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!("MCP 请求失败：已达到最大重试次数（{}次）", max_retries)
        }))
    }

    /// 内部方法：带重试逻辑的 API 调用
    ///
    /// 重试策略：
    /// - 每个凭据最多重试 MAX_RETRIES_PER_CREDENTIAL 次
    /// - 总重试次数 = min(凭据数量 × 每凭据重试次数, MAX_TOTAL_RETRIES)
    /// - 硬上限 9 次，避免无限重试
    async fn call_api_with_retry(
        &self,
        request_body: &str,
        is_stream: bool,
    ) -> anyhow::Result<reqwest::Response> {
        let total_credentials = self.token_manager.total_count();
        let max_retries = (total_credentials * MAX_RETRIES_PER_CREDENTIAL).min(MAX_TOTAL_RETRIES);
        let rate_limit_retries = self.rate_limit_retries_per_credential();
        let suspicious_rate_limit_retries = self.suspicious_rate_limit_retries_per_credential();
        let max_credential_rate_limit_retries =
            rate_limit_retries.max(suspicious_rate_limit_retries);
        let rate_limit_cooldown = self.rate_limit_cooldown();
        let max_cooled_credentials = self.rate_limit_max_cooled_credentials_per_request();
        let mut cooled_credentials = 0usize;
        let mut last_error: Option<anyhow::Error> = None;
        let mut force_refreshed: HashSet<u64> = HashSet::new();
        let api_type = if is_stream { "流式" } else { "非流式" };

        // 尝试从请求体中提取模型信息
        let model = Self::extract_model_from_request(request_body);

        'outer: for attempt in 0..max_retries {
            // 获取调用上下文（绑定 index、credentials、token）
            let ctx = match self.token_manager.acquire_context(model.as_deref()).await {
                Ok(c) => c,
                Err(e) => {
                    if self
                        .token_manager
                        .rate_limit_retry_after_seconds(model.as_deref())
                        .is_some()
                    {
                        return Err(self.all_credentials_rate_limit_error(
                            model.as_deref(),
                            Some(rate_limit_cooldown.as_secs()),
                        ));
                    }
                    last_error = Some(e);
                    continue;
                }
            };

            let endpoint = match self.endpoint_for(&ctx.credentials) {
                Ok(e) => e,
                Err(e) => {
                    last_error = Some(e);
                    self.token_manager.report_failure(ctx.id);
                    continue;
                }
            };

            for credential_attempt in 0..=max_credential_rate_limit_retries {
                let response = match self.send_api_once(&ctx, &endpoint, request_body).await {
                    Ok(resp) => resp,
                    Err(e) => {
                        tracing::warn!(
                            "API 请求发送失败（尝试 {}/{}）: {}",
                            attempt + 1,
                            max_retries,
                            e
                        );
                        // 网络错误通常是上游/链路瞬态问题，不应导致"禁用凭据"或"切换凭据"
                        // （否则一段时间网络抖动会把所有凭据都误禁用，需要重启才能恢复）
                        last_error = Some(e);
                        if attempt + 1 < max_retries {
                            sleep(Self::retry_delay(attempt)).await;
                        }
                        continue 'outer;
                    }
                };

                let status = response.status();

                // 成功响应
                if status.is_success() {
                    self.token_manager.report_success(ctx.id);
                    return Ok(response);
                }

                // 失败响应：读取 body 用于日志/错误信息
                let body = response.text().await.unwrap_or_default();

                if status.as_u16() == 429 {
                    let rate_limit_kind = Self::classify_rate_limit_body(&body);
                    let retries_for_kind = self.retries_for_rate_limit_kind(rate_limit_kind);
                    let cooldown_for_kind = self.cooldown_for_rate_limit_kind(rate_limit_kind);

                    if credential_attempt < retries_for_kind {
                        tracing::warn!(
                            "{} API 请求触发 429（类型 {}，凭据 #{}，账号内重试 {}/{}）: {}",
                            api_type,
                            rate_limit_kind.as_log_label(),
                            ctx.id,
                            credential_attempt + 1,
                            retries_for_kind,
                            body
                        );
                        sleep(Self::retry_delay(credential_attempt)).await;
                        continue;
                    }

                    tracing::warn!(
                        "{} API 请求凭据 #{} 触发 {} 429，进入冷却 {} 秒",
                        api_type,
                        ctx.id,
                        rate_limit_kind.as_log_label(),
                        cooldown_for_kind.as_secs()
                    );
                    cooled_credentials += 1;
                    let has_available = self
                        .token_manager
                        .report_rate_limited(ctx.id, cooldown_for_kind, rate_limit_kind.reason());
                    last_error = Some(self.all_credentials_rate_limit_error(
                        model.as_deref(),
                        Some(cooldown_for_kind.as_secs()),
                    ));
                    if !has_available {
                        return Err(last_error.unwrap());
                    }
                    if cooled_credentials >= max_cooled_credentials {
                        tracing::warn!(
                            "{} API 请求触发 429 熔断保护：本次请求已冷却 {} 个凭据，停止继续切换账号",
                            api_type,
                            cooled_credentials
                        );
                        return Err(self.per_request_rate_limit_error(
                            model.as_deref(),
                            Some(cooldown_for_kind.as_secs()),
                        ));
                    }
                    continue 'outer;
                }

                // 402 Payment Required 且额度用尽：禁用凭据并故障转移
                if status.as_u16() == 402 && endpoint.is_monthly_request_limit(&body) {
                    tracing::warn!(
                        "API 请求失败（额度已用尽，禁用凭据并切换，尝试 {}/{}）: {} {}",
                        attempt + 1,
                        max_retries,
                        status,
                        body
                    );

                    let has_available = self.token_manager.report_quota_exhausted(ctx.id);
                    if !has_available {
                        anyhow::bail!(
                            "{} API 请求失败（所有凭据已用尽）: {} {}",
                            api_type,
                            status,
                            body
                        );
                    }

                    last_error = Some(anyhow::anyhow!(
                        "{} API 请求失败: {} {}",
                        api_type,
                        status,
                        body
                    ));
                    continue 'outer;
                }

                // 400 Bad Request - 请求问题，重试/切换凭据无意义
                if status.as_u16() == 400 {
                    anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
                }

                // 401/403 - 更可能是凭据/权限问题：计入失败并允许故障转移
                if matches!(status.as_u16(), 401 | 403) {
                    tracing::warn!(
                        "API 请求失败（可能为凭据错误，尝试 {}/{}）: {} {}",
                        attempt + 1,
                        max_retries,
                        status,
                        body
                    );

                    // token 被上游失效：先尝试 force-refresh，每凭据仅一次机会
                    if endpoint.is_bearer_token_invalid(&body) && !force_refreshed.contains(&ctx.id)
                    {
                        force_refreshed.insert(ctx.id);
                        tracing::info!("凭据 #{} token 疑似被上游失效，尝试强制刷新", ctx.id);
                        if self.token_manager.force_refresh_token_for(ctx.id).await.is_ok() {
                            tracing::info!("凭据 #{} token 强制刷新成功，重试请求", ctx.id);
                            continue 'outer;
                        }
                        tracing::warn!("凭据 #{} token 强制刷新失败，计入失败", ctx.id);
                    }

                    let has_available = self.token_manager.report_failure(ctx.id);
                    if !has_available {
                        anyhow::bail!(
                            "{} API 请求失败（所有凭据已用尽）: {} {}",
                            api_type,
                            status,
                            body
                        );
                    }

                    last_error = Some(anyhow::anyhow!(
                        "{} API 请求失败: {} {}",
                        api_type,
                        status,
                        body
                    ));
                    continue 'outer;
                }

                // 408/5xx - 瞬态上游错误：重试但不禁用或切换凭据
                if status.as_u16() == 408 || status.is_server_error() {
                    tracing::warn!(
                        "API 请求失败（上游瞬态错误，尝试 {}/{}）: {} {}",
                        attempt + 1,
                        max_retries,
                        status,
                        body
                    );
                    last_error = Some(anyhow::anyhow!(
                        "{} API 请求失败: {} {}",
                        api_type,
                        status,
                        body
                    ));
                    if attempt + 1 < max_retries {
                        sleep(Self::retry_delay(attempt)).await;
                    }
                    continue 'outer;
                }

                // 其他 4xx - 通常为请求/配置问题：直接返回，不计入凭据失败
                if status.is_client_error() {
                    anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
                }

                // 兜底：当作可重试的瞬态错误处理（不切换凭据）
                tracing::warn!(
                    "API 请求失败（未知错误，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );
                last_error = Some(anyhow::anyhow!(
                    "{} API 请求失败: {} {}",
                    api_type,
                    status,
                    body
                ));
                if attempt + 1 < max_retries {
                    sleep(Self::retry_delay(attempt)).await;
                }
                continue 'outer;
            }
        }

        // 所有重试都失败
        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!(
                "{} API 请求失败：已达到最大重试次数（{}次）",
                api_type,
                max_retries
            )
        }))
    }

    /// 从请求体中提取模型信息
    ///
    /// 尝试解析 JSON 请求体，提取 conversationState.currentMessage.userInputMessage.modelId
    fn extract_model_from_request(request_body: &str) -> Option<String> {
        use serde_json::Value;

        let json: Value = serde_json::from_str(request_body).ok()?;

        json.get("conversationState")?
            .get("currentMessage")?
            .get("userInputMessage")?
            .get("modelId")?
            .as_str()
            .map(|s| s.to_string())
    }

    fn retry_delay(attempt: usize) -> Duration {
        // 指数退避 + 少量抖动，避免上游抖动时放大故障
        const BASE_MS: u64 = 200;
        const MAX_MS: u64 = 2_000;
        let exp = BASE_MS.saturating_mul(2u64.saturating_pow(attempt.min(6) as u32));
        let backoff = exp.min(MAX_MS);
        let jitter_max = (backoff / 4).max(1);
        let jitter = fastrand::u64(0..=jitter_max);
        Duration::from_millis(backoff.saturating_add(jitter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_suspicious_rate_limit_body() {
        let body = "Due to suspicious activity, we are imposing temporary limits while we investigate.";
        assert_eq!(
            KiroProvider::classify_rate_limit_body(body),
            UpstreamRateLimitKind::Suspicious
        );
    }

    #[test]
    fn test_classify_normal_rate_limit_body() {
        let body = r#"{"message":"Too many requests"}"#;
        assert_eq!(
            KiroProvider::classify_rate_limit_body(body),
            UpstreamRateLimitKind::Normal
        );
    }
}
