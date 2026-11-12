# Sealvault 电子证据保管

这是一个可独立运行的本地业务项目。核心模块保留数据接收、领域规则、持久化记录及查询接口；演练数据均为合成资料，不需要真实账号或外部业务服务。

## 运行环境

Python 3.11 或更新版本，核心业务使用标准库与 SQLite。
门户检查另外使用 Python 与 Playwright 1.56.0，浏览器为该版本安装的 Chromium。依赖与浏览器仅在镜像构建时安装。
Dockerfile 固定运行时版本。首次准备执行 docker build -t local-product .，之后以 docker run --rm --network none local-product 运行完整检查；所有 HTTP 演练只在容器内部回环地址通信。

## 开发与运行

业务测试：
    python -m unittest discover -s tests -v
编译或语法检查：
    python -m compileall -q sealvault demo_support
现有业务演示：
    python -m sealvault replay fixtures/sealing.json
输入端演练检查：
    python demo_support/check.py
合并运行：
    sh demo_support/verify.sh

输入协议、样本与故障开关见 demo_support/协议.md。输入端检查只证明本地来源的约定行为；业务演示展示当前已有功能。调用者可以在独立临时数据目录重复运行，原始样本不会被覆盖。

## 网页证据采集

`sealvault/capture/` 实现授权网页的可复核采集：接收一个 URL 与操作员预先批准的 origin/路径集合，在业务就绪且页面稳定后，从同一次稳定状态产出截图、最终 DOM 与信封式资源/导航清单，并按案件规则原子挂载为 `captures/<capture_id>/` 证据组。策略对每次导航和资源请求重新检查，禁用非 HTTP(S) 跳转与越界地址；cookies、Authorization 与浏览器持久配置不随证据保存。导航或版本改变导致整组重试或报告失败，浏览器失败或采集期间案件被封存都会留下原因且不挂载半组内容，重复确认不产生第二组附件。

浏览器端到端演练：
    python demo_support/capture_drill.py
单元测试覆盖策略、记录校验与采集台账（含封存竞态与幂等）：
    python -m unittest discover -s tests/capture -v
