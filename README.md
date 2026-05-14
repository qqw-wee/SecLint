# SecLint

一个轻量级、防御向的网络安全命令行小工具，用来检查网站的 HTTPS/TLS 配置、常见 HTTP 安全响应头和 Cookie 安全标记。

SecLint 的目标：输入一个 URL，它会返回 TLS 证书信息、缺失的安全响应头、Cookie 配置风险，以及一个简洁的加固评分。项目只依赖 Python 标准库，适合快速安全巡检、CI 冒烟检查、上线前配置复核或安全文档演示。

## 功能特性

- 检查常见 HTTP 安全响应头：
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
  - `Cross-Origin-Opener-Policy`
- 读取 TLS 证书的主题、签发者、过期时间和 DNS 名称。
- 提示已经过期或即将过期的证书。
- 检查 `Set-Cookie` 中的 `Secure`、`HttpOnly`、`SameSite` 标记。
- 输出一个简单的安全加固评分。
- 支持终端可读报告和 JSON 输出。

## 安装与运行

直接在项目目录中运行：

```bash
cd /225040511/project/headerhawk
PYTHONPATH=src python3 -m headerhawk https://example.com
```

也可以用可编辑模式安装：

```bash
cd /225040511/project/headerhawk
python3 -m pip install -e .
headerhawk https://example.com
```

## 使用示例

基础扫描：

```bash
headerhawk https://example.com
```

输出 JSON：

```bash
headerhawk https://example.com --json
```

设置超时时间：

```bash
headerhawk https://example.com --timeout 10
```

一次扫描多个目标：

```bash
headerhawk https://example.com https://www.python.org --json
```

## 示例输出

```text
https://example.com
Score: 71/100

TLS
  Common name: example.com
  Issuer: DigiCert Inc
  Expires: 2026-12-01T23:59:59Z
  Days remaining: 201

Headers
  [ok] Strict-Transport-Security
  [missing] Content-Security-Policy
    Add a CSP that limits script, style, frame, and object sources.
  [ok] X-Content-Type-Options
  [missing] X-Frame-Options
    Set DENY or SAMEORIGIN, or use CSP frame-ancestors.
```

## 评分说明

HeaderHawk 会从 100 分开始扣分：

- 缺少常见安全响应头会扣分。
- 目标没有使用 HTTPS 会扣分。
- TLS 证书异常、过期或即将过期会扣分。
- Cookie 缺少推荐安全标记会扣分。

这个分数不是严格的合规结论，而是一个快速排查线索。真实生产环境还需要结合业务场景、反向代理配置、认证逻辑和浏览器兼容性一起评估。

## 防御黑客攻击

HeaderHawk 不能替代完整的渗透测试或 WAF，但它可以帮助你发现一些常见的 Web 安全配置缺口。这些缺口经常被攻击者用来扩大 XSS、点击劫持、会话窃取、降级访问和跨站数据泄露等风险。

建议把它用于以下防御场景：

- 上线前检查：在新服务发布前扫描一次，确认基础安全响应头没有遗漏。
- CI/CD 安全门禁：把 `headerhawk --json` 接入流水线，对缺失关键响应头的服务发出告警。
- 反向代理复核：检查 Nginx、Caddy、Traefik、CDN 或 API Gateway 是否正确注入安全头。
- TLS 证书巡检：提前发现证书即将过期、证书链异常或站点没有启用 HTTPS。
- 会话 Cookie 加固：确认登录态 Cookie 使用了 `Secure`、`HttpOnly` 和 `SameSite`。
- 安全基线审计：定期扫描公开域名，生成 JSON 结果用于对比历史配置变化。

常见加固方向：

| 风险类型 | 推荐配置 | 防御价值 |
| --- | --- | --- |
| HTTPS 降级访问 | `Strict-Transport-Security` | 强制浏览器优先使用 HTTPS，降低中间人攻击风险 |
| XSS 扩大影响 | `Content-Security-Policy` | 限制脚本、样式、图片和 iframe 的加载来源 |
| MIME 嗅探 | `X-Content-Type-Options: nosniff` | 防止浏览器错误解析资源类型 |
| 点击劫持 | `X-Frame-Options` 或 CSP `frame-ancestors` | 限制页面被恶意 iframe 嵌入 |
| 隐私泄露 | `Referrer-Policy` | 减少跨站跳转时泄露敏感 URL 信息 |
| 浏览器能力滥用 | `Permissions-Policy` | 禁用不需要的摄像头、麦克风、定位等能力 |
| 会话窃取 | Cookie `Secure`、`HttpOnly`、`SameSite` | 降低明文传输、脚本读取和跨站请求风险 |

一个简单的防御工作流：

```bash
# 1. 扫描公开站点并输出 JSON
headerhawk https://example.com --json > security-baseline.json

# 2. 修改反向代理或应用响应头配置
# 3. 再次扫描并比较结果
headerhawk https://example.com
```

如果你使用 Nginx，可以参考下面的响应头配置片段：

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

`Content-Security-Policy` 需要结合具体业务谨慎配置。可以先从报告模式开始观察：

```nginx
add_header Content-Security-Policy-Report-Only "default-src 'self'; object-src 'none'; frame-ancestors 'self'" always;
```

## 安全边界

HeaderHawk 只做被动检查：

- 读取公开 HTTP 响应头
- 读取公开 TLS 证书信息
- 分析响应中的 Cookie 标记
- 不爆破
- 不利用漏洞
- 不 fuzz
- 不爬取站点
- 不尝试绕过认证

请只扫描你拥有或明确获得授权的系统。

## 退出码

- `0`：所有扫描完成
- `1`：一个或多个目标扫描失败
- `2`：命令行参数错误

## 开发

运行测试：

```bash
python3 -m pytest
```

不安装，直接以模块方式运行：

```bash
PYTHONPATH=src python3 -m headerhawk https://example.com
```

项目结构：

```text
headerhawk/
  src/headerhawk/
    cli.py
    scanner.py
  tests/
    test_scanner.py
  README.md
  pyproject.toml
```

## 📄 License

MIT
