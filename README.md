# ruleset-builder

用于 GitHub Actions 自动构建 Mihomo 规则集。

## 核心流程

1. `collections`：定义可复用的上游集合，只下载一次并在本次构建中复用。
2. `rulesets.sources`：把多个集合、URL、MRS、Clash YAML、inline 规则组合起来，去重。
3. `rulesets.exclude`：按语义从最终集合中剔除另一个集合。
4. `output`：输出 `.list`、Clash YAML，或使用 Mihomo `convert-ruleset` 编译为 `.mrs`。

## 支持的行为

- `behavior: domain`
  - 输入：普通域名列表、`DOMAIN`、`DOMAIN-SUFFIX`、Clash YAML、domain MRS、inline。
  - 输出：domain `.list`、domain YAML 或 domain `.mrs`。
  - 排除：按父域/子域关系剔除。
- `behavior: ipcidr`
  - 输入：IPv4/IPv6 CIDR、`IP-CIDR`、`IP-CIDR6`、IP MRS、inline。
  - 单个 IP 会标准化为 `/32` 或 `/128`。
  - 输出：CIDR `.list`、CIDR YAML 或 ipcidr `.mrs`。
  - 排除：按网段包含/重叠关系剔除。

## 配置示例

```yaml
collections:
  github:
    url: https://example.com/github.list
    type: list

  microsoft:
    url: https://example.com/microsoft.list
    type: list

  cn-ip:
    url: https://example.com/cn-ip.list
    type: list

rulesets:
  microsoft:
    behavior: domain
    output: mrs
    sources:
      - ref: microsoft
    exclude:
      - ref: github

  cn-ip:
    behavior: ipcidr
    output: mrs
    sources:
      - ref: cn-ip
```

生成文件位于 `ruleset/`。

## 本地测试

```powershell
py -m pip install -r requirements.txt
py -m pytest -q
py scripts/build.py --only microsoft --mihomo C:\path\to\mihomo.exe
```

如果只验证解析/剔除逻辑，不需要联网；如果需要生成 MRS，则必须提供 Mihomo 可执行文件。

### YAML 输出示例

```yaml
rulesets:
  microsoft:
    behavior: domain
    output: yaml
    sources:
      - ref: microsoft
    exclude:
      - ref: github
```

生成 `ruleset/microsoft.yaml`，格式为：

```yaml
payload:
  - +.example.com
```
