# Shadowrocket Clash Rules

将 [GMOogway/shadowrocket-rules](https://github.com/GMOogway/shadowrocket-rules) 的代理、拒绝和直连模块转换为 Clash/Mihomo 可订阅的规则集。三个模块从同一个上游提交拉取。

## GitHub Actions

把项目提交到 GitHub，设 `main` 为默认分支。工作流每天 **05:23 UTC** 同步一次。也可以在仓库的 **Actions → Sync Clash rules → Run workflow** 手动同步。脚本、测试或工作流更新时也会触发同步。

工作流使用仓库自带的 `GITHUB_TOKEN`。转换成功且规则内容有变化时，才会提交六个规则文件。下载失败或源模块条数校验失败时，GitHub Raw 继续提供上一次成功发布的规则。

## 接入 Clash / Mihomo

将项目发布到公开 GitHub 仓库后，把下例 URL 中的 `FairylandTech/proxy-roles` 换成你自己的仓库路径。使用 `🌐 节点选择` 作为代理组，或将它替换为你已有的代理组名称。

```yaml
rule-providers:
  shadowrocket_reject_domains:
    type: http
    behavior: domain
    format: text
    interval: 86400
    url: https://raw.githubusercontent.com/FairylandTech/proxy-roles/main/rules/reject-domains.txt
  shadowrocket_proxy_domains:
    type: http
    behavior: domain
    format: text
    interval: 86400
    url: https://raw.githubusercontent.com/FairylandTech/proxy-roles/main/rules/proxy-domains.txt
  shadowrocket_proxy_patterns:
    type: http
    behavior: classical
    format: text
    interval: 86400
    url: https://raw.githubusercontent.com/FairylandTech/proxy-roles/main/rules/proxy-patterns.txt
  shadowrocket_direct_domains:
    type: http
    behavior: domain
    format: text
    interval: 86400
    url: https://raw.githubusercontent.com/FairylandTech/proxy-roles/main/rules/direct-domains.txt
  shadowrocket_direct_patterns:
    type: http
    behavior: classical
    format: text
    interval: 86400
    url: https://raw.githubusercontent.com/FairylandTech/proxy-roles/main/rules/direct-patterns.txt
  shadowrocket_proxy_ips:
    type: http
    behavior: classical
    format: text
    interval: 86400
    url: https://raw.githubusercontent.com/FairylandTech/proxy-roles/main/rules/proxy-ips.txt

rules:
  - RULE-SET,shadowrocket_reject_domains,REJECT
  - RULE-SET,shadowrocket_proxy_domains,🌐 节点选择
  - RULE-SET,shadowrocket_proxy_patterns,🌐 节点选择
  - RULE-SET,shadowrocket_direct_domains,DIRECT
  - RULE-SET,shadowrocket_direct_patterns,DIRECT
  - RULE-SET,shadowrocket_proxy_ips,🌐 节点选择
```

接入已有配置时，合并到现有的 `rule-providers` 和 `rules`。从内置版迁移时，可以沿用上例同名规则集的 `RULE-SET` 引用和原有位置，只替换规则集定义。首次下载完成后，客户端按 `interval` 刷新。

## 本地运行

```sh
python3 -m unittest discover -s tests
python3 sync_rules.py
```

脚本只使用 Python 标准库。域名规则保留精确和后缀匹配，关键字、主机名正则和 IP 段使用 Classical 格式。可识别的主机型 URL 正则转换为主机名匹配。依赖 HTTP 路径或 User-Agent 的规则会跳过，并在同步日志中显示数量。

项目发布的文件来自上游三个公开模块。来源和授权见 [上游仓库](https://github.com/GMOogway/shadowrocket-rules) 与 [GPL-3.0 许可证](LICENSE)。
