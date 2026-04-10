# sysinfo_panel

一个轻量的系统信息面板，基于 Node.js 原生 HTTP 服务实现。

> 目标：`git clone` 后几乎零配置即可直接启动。

## 项目结构

- `server.js`：主服务与页面渲染
- `start.sh`：启动脚本
- `package.json`：项目元信息与脚本
- `docs/PROJECT.md`：项目结构说明
- `data/`：本地配置（默认不提交）
- `logs/`：运行日志（默认不提交）
- `certs/`：证书目录（默认不提交）

## 当前特性

- 登录鉴权
- 系统概览
- 网络接口展示
- 磁盘使用展示
- 监听端口展示
- Docker 容器页
- Docker 容器详情页（状态 / 镜像 / 端口 / 启动时间 / 重启次数 / 最近日志）
- Docker 容器操作（启动 / 停止 / 重启）
- systemd 服务状态页
- systemd 服务详情页（状态 / MainPID / 启动时间 / unit 文件 / 最近日志）
- systemd 服务操作（启动 / 停止 / 重启）
- 日志查看页（系统日志 / OpenClaw / Nginx / Docker / 认证日志）
- 告警中心
- 进程监控页（PID / CPU / 内存 / 命令）
- 自动刷新
- 自定义刷新时间
- 模块页搜索过滤
- 模块页一键复制
- 危险操作页内确认
- 右下角浮动时间盒子
- 基础移动端 / 平板端适配
- 赛博风界面与动效
- 赛博流星与像素块背景特效

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/TlyHj/sysinfo_panel.git
cd sysinfo_panel
```

### 2. 启动

```bash
npm start
```

或：

```bash
bash ./start.sh
```

### 3. 默认登录

首次启动会自动生成运行目录与认证配置。

- 用户名：`admin`
- 密码：`123456`

## 运行机制

- 首次启动自动创建 `data/` 和 `logs/`
- 首次启动自动生成 `data/config.json`
- 仓库内不提交运行期密码文件、配置文件、日志文件
- 示例配置见：`data.example/config.example.json`

## 默认监听

- `127.0.0.1:18888`
- 基础路径：`/sysinfo`

也支持环境变量覆盖：

```bash
PORT=18989 HOST=127.0.0.1 BASE_PATH=/sysinfo npm start
```

## 页面能力补充

- 首页保留核心概览与告警摘要
- 各模块支持独立详情页
- 详情页支持页内搜索 / 过滤
- 详情页支持一键复制当前模块内容
- 进程监控页支持查看高占用进程明细
- 服务页支持查看详情、最近日志与直接操作
- Docker 页支持查看详情、最近日志与直接操作
- stop / restart 等危险动作需要先在页内勾选确认

## 说明

仓库默认不包含：

- 运行日志
- 本地配置
- 密码文件
- 证书文件
- 其他运行期敏感数据
