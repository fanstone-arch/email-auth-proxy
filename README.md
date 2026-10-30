
Light-Auth-Proxy (轻量级零信任邮箱验证码认证网关)

🎨 零依赖、高性能、单文件的通用反向代理身份认证网关。支持通过企业/个人邮箱验证码，对任意后端 Web 系统（如泛微 OA、NAS 控制台、Jenkins、GitLab 等）实施前置接入零信任（ZTA）安全合规拦截。

📖 项目背景与痛点

在多年管理集团信息化系统的实战中，网络安全形势愈加严峻。特别是政府、央国企的各类信息化系统，对网络安全的合规与防护要求极高。ERP、OA 等面向特定内部人群的系统一旦直接对公网开放，常常面临高危漏洞扫描、勒索病毒注入等严重威胁。
传统上，企业多采用 VPN 虚拟内网进行隔离，但这带来了需要频繁安装客户端、移动端配置繁琐、用户体验割裂等不便。为此，我们在日常管理中引入了零信任（Zero Trust）方案：
• PC端：原方案基于 OpenResty 拦截未认证流量，重定向到二维码页面，使用企业微信扫码进行身份验证，并在 Session 剩余时长较少时自动续期，保障高频活跃用户的无感免登体验。
• 移动端：在企业微信内置浏览器中实施静默认证，实现客户端的完全无感接入。
然而，在实际落地中，我们发现了一个高频的“安全认证死角”：
以泛微 OA 对应的移动端 App（如 e-mobile7）为例，作为独立客户端，它既无法在内网直接扫码，也无法触发企业微信内置浏览器的静默认证链接。
为了不破坏整网的零信任闭环，邮箱验证码机制成为了最完美的兜底和补充方案（emobile7 登录补充）：
1. 为什么不用手机短信？ 很多外部合作用户在企业内部系统并未登记手机号，且短信需要对接昂贵的第三方短信服务商网关；而配置标准的 SMTP 发信服务几乎是零门槛、零预算。
2. 更广阔的应用场景：除了完美解决企业级 App 认证死角外，该项目的轻量化单文件特性，能以零额外预算的优势，完美保护个人用户的 NAS 私有云、私有开发项目等，阻断公网黑客对高危漏洞的刺探。

✨ 核心特性

• 🚀 极致单文件分发：基于 Go 语言研发，摆脱了传统 OpenResty 繁琐的 Lua 依赖库、网络解析与容器束缚，一个二进制文件、零依赖环境即可在 Linux/Windows 生产环境秒级上线。
• 🔑 跨子域单点登录 (SSO)：支持主域名级别（Domain）的 Cookie 凭证共享。员工在 ://company.com 验证一次，访问同一主域下的 ://company.com、://company.com 即可全自动免登放行。
• 🔄 智能平滑双向续期：支持动态滑动续期窗口（Sliding Window）。当 Session 剩余寿命低于设定阈值且用户依然活跃时，系统自动无感重刷内存与浏览器 Cookie 周期。
• 🛡️ 身份级别智能动态分流：
	• 管理员固定访问路径 /auth/admin/monitor，系统基于当前合法的登录身份自动判定：
	• 若非管理员账号（普通员工）：网关自动放行，将其作为普通业务流量原封不动转发给后端真实系统，完美解决管理路径与业务路径发生命名冲突的生产隐患。
	• 若是管理员账号：就地精准截断，渲染出全中文的图形化会话监控中心大屏。
• 📈 工业级生产调优对齐：
	• 大文件上传保护：内置 MaxBodySize 过滤器（对齐 client_max_body_size 200m），防止大文件或恶意请求撑爆系统内存。
	• 内存级缓冲复用：利用 Go 原生 sync.Pool 建立高效内存缓冲池（对齐 proxy_buffers），在大附件上传下载、多数据流高并发下保持极低的 GC 抖动。
	• 安全指纹擦除：中间件强行抹除或修改 Go 的默认 Server 协议头（对齐 more_clear_headers 'Server'），防范黑客恶意指纹扫描。
	• XSS 安全防御：自动向所有保护的下游系统统一注入安全响应头 X-XSS-Protection "1; mode=block"。
• 📬 自适应双模发信引擎：发信逻辑完美兼容 465 纯 SSL 加密通道 与 25/587 普通 TCP/STARTTLS 自适应升级通道。
• 🔄 原路重定向回跳：用户未登录时访问深层业务 URL（如 /wui/index.html?id=99），网关强拦截并完整保留请求参数轨迹，验证成功后秒级精准原路带回原页面。
• 🌍 全栈多语言自适应 (i18n)：前端登录卡片、后端异常报错、邮件投递正文、以及管理员审计大屏，全部支持根据浏览器的系统语种动态自适应切换（中文/英文）。

🛠️ 快速开始


1. 部署配置文件 config.yaml

在程序同级目录下创建 config.yaml，内容如下：
yaml
# 1. 端口监听配置：可同时启动多组普通 HTTP 端口和 SSL HTTPS 端口
listeners:
  - http_port: ":80"            # 普通 HTTP 监听端口
    #https_port: ":443"          # SSL HTTPS 监听端口（如果启用HTTPS，三项注销并填写相应的内容）
    #ssl_crt: "/root/email-auth-proxy/ssl/fullchain.pem" # 你的域名证书路径
    #ssl_key: "/root/email-auth-proxy/ssl/privkey.pem" # 你的域名私钥路径

# 2. 统一全局认证与 Cookie 状态管理
server:
  cookie_name: "auth_session"
  cookie_domain: ".yourdomain.com"     # ⚠️ 设为主域名作用域，所有子域名即可无缝共享登录状态,若使用ip，则这里和route的host都是ip
  max_body_size: 209715200             #如200M ，1024*1024*200=209715200

auth:
  session_ttl: 172800              # 登录状态总保持时长（秒，此处为48小时3600*48=172800）
  renew_trigger_ttl: 86400        # 智能平滑续期触发线（秒）：少于此剩余时间时自动刷新为满额 TTL。未配置默认关闭
  allowed_emails:                # 白名单
    - "yourname@yourdomain.com"
    - "ortheremail@cyourdomain.com"
  admin_emails:          # ⚠️ 新增：只有在这里登记的邮箱，才有权限访问网页端会话监控面板
    - "admin@cyourdomain.com"    

# 3. 自适应发信服务器配置（完美支持自建邮、企业邮双模）
smtp:
  host: "smtp.yourhost.com"          #腾讯qq的:smtp.qq.com
  port: "465"                    # 端口号（例如 465, 587, 25）
  ssl_enabled: true             # ⚠️ 新增：true 代表465纯SSL加密；false代表25/587非纯SSL(支持自动升级STARTTLS)
  user: "yourusername"
  pass: "yourpassword"
# 4. 高级动态路由分发表：一个认证同时对应分发多个子域名与后缀路径
routes:
  - host: "host1.yourdomain.com"         # 访问当前域名时
    path: "/"                    # 匹配的根路径
    backend: "http://127.0.0.1:8888" # 转发给后端真实业务系统 A
  
  - host: "host2.yourdomain.com"        # 访问当前域名时
    path: "/"
    backend: "http://192.168.0.2:8080" # 转发给后端真实业务系统 B
Use code with caution.

2. 部署运行


方式 A：直接下载成品二进制单文件

您可以直接在 GitHub 的 Releases 页面下载对应系统的编译好文件（支持 Linux-amd64、Linux-arm64、Windows、Mac），赋予执行权限后直接启动。支持使用 -config 参数实现程序与配置文件的跨目录维护：
bash
chmod +x ./auth-proxy
./auth-proxy -config /etc/auth-proxy/config.yaml
Use code with caution.

方式 B：Linux 生产环境守护进程 (Systemd)

创建系统服务配置文件：nano /etc/systemd/system/auth-proxy.service，粘贴以下脚本：
ini
[Unit]
Description=Lightweight Email Auth Proxy Gateway
After=network.target

[Service]
Type=simple
WorkingDirectory=/root/email-auth-proxy
ExecStart=/root/email-auth-proxy/auth-proxy
Restart=always
RestartSec=5s
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=auth-proxy

[Install]
WantedBy=multi-user.target
Use code with caution.
启动并开启开机自启：
bash
systemctl daemon-reload
systemctl enable auth-proxy
systemctl start auth-proxy
Use code with caution.

🖥️ 监控与运维管理面板

系统管理员使用配置的管理员邮箱登录成功后，直接在浏览器中访问统一固定的管理入口：
https://您的任何业务域名:端口/auth/admin/monitor
大屏监控台功能亮点：
• 身份动态染色：自动区分展现 管理员（橙色）与 用户（蓝色）会话标签。
• 脱敏前缀显示：自动对 Token 执行前缀裁剪脱敏显示，既保障会话唯一性确认，又杜绝屏幕泄漏导致安全凭证被截获。
• 无感远程阻断（踢）：点击右侧的 “踢” 按钮，后端内存对应的 Session 瞬间被粉碎。该员工在下一次点击系统的零点几秒内，会直接被网关剥夺权限并强制弹回登录验证码页面。

🛠️ CI/CD 自动化流水线说明

项目内置了标准的 .github/workflows/release.yml 自动化工作流脚本。每当您在本地代码打上以 v 开头的 Tag 标签（如 v1.0.2）推送到 GitHub 时，GitHub Actions 会自动拉起纯净的云端虚拟机，全自动并发交叉编译出全平台优化裁剪后的成品资产包挂载在 Releases 页面。

📜 开源协议

本项目基于 MIT 协议开源，欢迎提交 Issue 与 Pull Request！