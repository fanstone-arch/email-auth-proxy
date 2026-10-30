package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag" 
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/smtp"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"html/template"

	"gopkg.in/yaml.v3"
)

type ListenerRule struct {
	HttpPort  string `yaml:"http_port"`
	HttpsPort string `yaml:"https_port"`
	SslCrt    string `yaml:"ssl_crt"`
	SslKey    string `yaml:"ssl_key"`
}

type RouteRule struct {
	Host    string `yaml:"host"`
	Path    string `yaml:"path"`
	Backend string `yaml:"backend"`
}

type Config struct {
	Listeners []ListenerRule `yaml:"listeners"`
	Server    struct {
		CookieName   string `yaml:"cookie_name"`
		CookieDomain string `yaml:"cookie_domain"`
		MaxBodySize  int64  `yaml:"max_body_size"`
	} `yaml:"server"`
	Auth struct {
		SessionTTL      int64    `yaml:"session_ttl"`
		RenewTriggerTTL int64    `yaml:"renew_trigger_ttl"` // 智能平滑续期触发阈值线
		AllowedEmails   []string `yaml:"allowed_emails"`
		AdminEmails     []string `yaml:"admin_emails"`
	} `yaml:"auth"`
	Smtp struct {
		Host       string `yaml:"host"`
		Port       string `yaml:"port"`
		SslEnabled bool   `yaml:"ssl_enabled"` // 自适应双模发信开关
		User       string `yaml:"user"`
		Pass       string `yaml:"pass"`
	} `yaml:"smtp"`
	Routes []RouteRule `yaml:"routes"`
}

type codeRecord struct {
	Code      string
	ExpiresAt time.Time
}

type sessionRecord struct {
	Email     string
	ExpiresAt time.Time
}

type rateLimitRecord struct {
	Count     int
	ExpiresAt time.Time
}

var (
	cfg           Config
	codesStore    sync.Map
	tryStore      sync.Map
	cooldownStore sync.Map
	ipLimitStore  sync.Map
	sessionsStore sync.Map
	allowedMap    = make(map[string]bool)
	adminMap      = make(map[string]bool)
	globalBufPool *byteBufferPool
	configPath    string
)

type byteBufferPool struct {
	pool sync.Pool
}
func (p *byteBufferPool) Get() []byte  { return p.pool.Get().([]byte) }
func (p *byteBufferPool) Put(b []byte) { p.pool.Put(b) }

func main() {
	// 1. ⚙️ 定义命令行参数：参数名叫 -config，默认值是 "config.yaml"，后面是功能说明
	flag.StringVar(&configPath, "config", "config.yaml", "指定配置文件 config.yaml 的绝对或相对路径")
	
	// 2. 核心：让 Go 开始解析输入执行的参数
	flag.Parse()

	// 3. ⚠️ 动态加载：把解析到的 configPath 传给加载函数，不再写死文件名
	loadConfig(configPath)



	for _, email := range cfg.Auth.AllowedEmails {
		allowedMap[strings.ToLower(email)] = true
	}
	for _, email := range cfg.Auth.AdminEmails {
		adminEmail := strings.ToLower(email)
		adminMap[adminEmail] = true
		
		// 让管理员自动继承登录权限，无需在 AllowedEmails 里重复配置
		allowedMap[adminEmail] = true 
		log.Printf("🛡️ [安全初始化] 管理员账号 [%s] 已自动注入白名单并获得登录权限", adminEmail)
	}

	// 智能阈值默认值处理：若未配置，则默认为总 Session 时长的一半
	/*
	if cfg.Auth.RenewTriggerTTL <= 0 {
		cfg.Auth.RenewTriggerTTL = cfg.Auth.SessionTTL / 2
	}
	*/
	// 👈 加上这行：如果没有配，则默认给 200m 缓冲区
	if cfg.Server.MaxBodySize <= 0 {
		cfg.Server.MaxBodySize = 209715200 
	}

	// 👈 加上这行：初始化内存缓冲池
	globalBufPool = &byteBufferPool{
		pool: sync.Pool{
			New: func() interface{} { return make([]byte, 32768) },
		},
	}
	go startMemoryCleaner()

	// 👈 这里重构路由注册方式，以便套上全局生产级中间件
	mainHandler := http.NewServeMux()
	mainHandler.HandleFunc("/auth/send", handleSend)
	mainHandler.HandleFunc("/auth/verify", handleVerify)
	mainHandler.HandleFunc("/auth/admin/monitor", handleMonitorPage)     // 1. 监控网页渲染
	mainHandler.HandleFunc("/auth/admin/api/list", handleSessionListAPI)  // 2. 异步刷新列表数据 API
	mainHandler.HandleFunc("/auth/admin/api/kick", handleKickSessionAPI) // 3. 强行踢人下线 API
	mainHandler.HandleFunc("/", handleProxyGateway)	
	
	wrappedHandler := productionMiddleware(mainHandler)



	// 利用 Goroutine 并发机制启动多端口监听
	var wg sync.WaitGroup
	for _, l := range cfg.Listeners {
		// 1. 满足 HTTPS 证书条件，启动安全加密服务器
		if l.HttpsPort != "" && l.SslCrt != "" && l.SslKey != "" {
			wg.Add(1)
			go func(rule ListenerRule) {
				defer wg.Done()
				log.Printf("[HTTPS 监听已就绪] 端口 %s\n", rule.HttpsPort)
				// ⚠️ 核心注意：把最后一个参数由 nil 或原来的值 换成 wrappedHandler
				if err := http.ListenAndServeTLS(rule.HttpsPort, rule.SslCrt, rule.SslKey, wrappedHandler); err != nil {
					log.Printf("❌ HTTPS服务 %s 异常退出: %v\n", rule.HttpsPort, err)
				}
			}(l)

			// 2. 同时配置了 http_port，则让 HTTP 端口自动扮演 301 重定向跳转 HTTPS 的保护角色
			if l.HttpPort != "" {
				wg.Add(1)
				go func(rule ListenerRule) {
					defer wg.Done()
					log.Printf("[HTTP 重定向已就绪] 端口 %s -> 强制跳转安全链接\n", rule.HttpPort)
					redirectServer := &http.Server{
						Addr: rule.HttpPort,
						Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							host := r.Host
							if idx := strings.Index(host, ":"); idx != -1 {
								host = host[:idx]
							}
							_, port, _ := strings.Cut(rule.HttpsPort, ":")
							targetURL := fmt.Sprintf("https://%s:%s%s", host, port, r.URL.RequestURI())
							http.Redirect(w, r, targetURL, http.StatusMovedPermanently)
						}),
					}
					if err := redirectServer.ListenAndServe(); err != nil {
						log.Printf("❌ HTTP重定向服务 %s 异常退出: %v\n", rule.HttpPort, err)
					}
				}(l)
			}
		} else if l.HttpPort != "" {
			// 3. 未配置证书，只作为标准纯 HTTP 专属网关监听端口
			wg.Add(1)
			go func(rule ListenerRule) {
				defer wg.Done()
				log.Printf("[HTTP 监听已就绪] 端口 %s\n", rule.HttpPort)
				// ⚠️ 核心注意：把最后一个参数由 nil 或原来的值 换成 wrappedHandler
				if err := http.ListenAndServe(rule.HttpPort, wrappedHandler); err != nil {
					log.Printf("❌ HTTP服务 %s 异常退出: %v\n", rule.HttpPort, err)
				}
			}(l)
		}
	}

	wg.Wait()

}


// 👈 并在 main() 函数下方，直接贴入这个全新的中间件函数：
func productionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, cfg.Server.MaxBodySize) // 限制文件最大200m
		w.Header().Set("X-XSS-Protection", "1; mode=block")           // XSS防御
		w.Header().Set("Server", "Secure-Auth-Gateway")               // 擦除并伪装Server特征
		next.ServeHTTP(w, r)
	})
}

// 核心多域名反向代理与强拦截网关
func handleProxyGateway(w http.ResponseWriter, r *http.Request) {
	// 1. 如果访问的是基础登录认证页路由，直接放行
	if r.URL.Path == "/auth/login-page" {
		serveVerifyPage(w, r)
		return
	}

	// ⚠️ 终极精准截断修复：支持完全对齐前台 fetch 请求的智能路由分流
	// 我们严格检查当前请求的路径是否属于管理面板或驱动 API
	if r.URL.Path == "/auth/admin/monitor" || r.URL.Path == "/auth/admin/api/list" || r.URL.Path == "/auth/admin/api/kick" {
		cookie, err := r.Cookie(cfg.Server.CookieName)
			if err != nil || !validateSession(cookie.Value, w) {
				scheme := "http"
				if r.TLS != nil {
					scheme = "https"
				}
				
				// 💡 终极修复：这里强制使用浏览器带过来的、最原始、原汁原味带端口的 r.Host（例如 tax.yourdomain.cn:81）
				// 绝对不能使用被裁剪了端口的临时域名变量！
				originalTarget := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.RequestURI())
				loginURL := fmt.Sprintf("%s://%s/auth/login-page?target=%s", scheme, r.Host, url.QueryEscape(originalTarget))
				
				http.Redirect(w, r, loginURL, http.StatusFound)
				return
			}
		
		// 💡 智能分流：如果是普通员工（非管理员），代码会自动流到这里，
		// 跳过本地大屏渲染，原原封不动地发给后端业务系统，安全无冲突！
	}

	// ---- 以下原有的标准身份审计、未登录强制跳转认证页及多域名 Routes 转发逻辑 100% 保持不变 ----
	cookie, err := r.Cookie(cfg.Server.CookieName)
	if err != nil || !validateSession(cookie.Value, w) {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		originalTarget := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.RequestURI())
		loginURL := fmt.Sprintf("%s://%s/auth/login-page?target=%s", scheme, r.Host, url.QueryEscape(originalTarget))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}
    
    // ... 后续反向代理及请求头清洗逻辑完全保持不变

	var targetBackend string
	currentHost := strings.ToLower(r.Host)
	if idx := strings.Index(currentHost, ":"); idx != -1 {
		currentHost = currentHost[:idx]
	}

	for _, rule := range cfg.Routes {
		if (rule.Host == "" || strings.ToLower(rule.Host) == currentHost) && strings.HasPrefix(r.URL.Path, rule.Path) {
			targetBackend = rule.Backend
			break
		}
	}

	if targetBackend == "" {
		http.Error(w, fmt.Sprintf("网关未配置此域名 [%s] 或路径 [%s] 的转发映射规则 (404 Not Found)", currentHost, r.URL.Path), http.StatusNotFound)
		return
	}

	if strings.HasSuffix(targetBackend, "/") {
		targetBackend = strings.TrimSuffix(targetBackend, "/")
	}

	target, err := url.Parse(targetBackend)
	if err != nil {
		http.Error(w, "后端业务服务 URL 解析失败", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.BufferPool = globalBufPool // 👈 绑定大附件缓冲池

	r.URL.Host = target.Host
	r.URL.Scheme = target.Scheme
	
	cleanedPath := target.Path + r.URL.Path
	if strings.HasPrefix(cleanedPath, "//") {
		cleanedPath = strings.TrimPrefix(cleanedPath, "/")
	}
	r.URL.Path = cleanedPath

	// 💡 极其关键：对齐你发过来的原 Nginx 生产环境代理头，缺少这些泛微就会报 404！
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	r.Header.Set("X-Forwarded-Proto", scheme)
	r.Header.Set("X-Forwarded-Host", r.Host)
	r.Header.Set("X-Forwarded-For", getRemoteIP(r))
	r.Header.Set("X-Real-IP", getRemoteIP(r))
	r.Header.Set("X-Forwarded-Port", "443")
	
	r.Host = r.Host // 保持原始访问域名透传

	if sess, ok := sessionsStore.Load(cookie.Value); ok {
		r.Header.Set("X-Auth-User-Email", sess.(sessionRecord).Email)
	}

	proxy.ServeHTTP(w, r)
}


func handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		replyJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"ok": false, "msg": "Method not allowed"})
		return
	}

	// ⚠️ 自动判定当前请求的语言环境（检查请求头 Accept-Language）
	isEn := !strings.Contains(strings.ToLower(r.Header.Get("Accept-Language")), "zh")

	bodyBytes, _ := io.ReadAll(r.Body)
	var reqData map[string]string
	json.Unmarshal(bodyBytes, &reqData)
	email := strings.ToLower(strings.TrimSpace(reqData["email"]))
	ip := getRemoteIP(r)

	now := time.Now()
	if val, ok := ipLimitStore.Load(ip); ok {
		rec := val.(rateLimitRecord)
		if now.Before(rec.ExpiresAt) {
			if rec.Count >= 20 {
				msg := "请求过于频繁，请稍后再试"
				if isEn { msg = "Too many requests, please try again later" }
				replyJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "msg": msg})
				return
			}
			rec.Count++
			ipLimitStore.Store(ip, rec)
		} else {
			ipLimitStore.Store(ip, rateLimitRecord{Count: 1, ExpiresAt: now.Add(5 * time.Minute)})
		}
	} else {
		ipLimitStore.Store(ip, rateLimitRecord{Count: 1, ExpiresAt: now.Add(5 * time.Minute)})
	}

	emailRegex := regexp.MustCompile(`^[\w%.+%-]+@[\w%.%-]+\.[\w%.%-]+$`)
	if len(email) > 128 || !emailRegex.MatchString(email) {
		msg := "邮箱格式不正确"
		if isEn { msg = "Invalid email format" }
		replyJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "msg": msg})
		return
	}

	if !allowedMap[email] {
		msg := "该邮箱未登记，请联系管理员开通"
		if isEn { msg = "This email is not registered, please contact admin" }
		replyJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "msg": msg})
		return
	}

	if cd, ok := cooldownStore.Load(email); ok {
		if now.Before(cd.(time.Time)) {
			msg := "验证码已发送，请勿频繁获取"
			if isEn { msg = "Verification code already sent, please wait" }
			replyJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "msg": msg})
			return
		}
	}
	cooldownStore.Store(email, now.Add(60*time.Second))

	code := generateRandomCode()
	codesStore.Store(email, codeRecord{Code: code, ExpiresAt: now.Add(5 * time.Minute)})
	tryStore.Store(email, 0)

	log.Printf("🔥 [本地测试提示] 邮箱: %s 申请了验证码，本次生成的验证码为: 【 %s 】", email, code)

	// 找到大约 180 行附近的这一段，加上 isEn 变量传递
	err := sendMail(email, code, isEn) // 👈 传入当前探测出的语言环境
	if err != nil {
		log.Printf("❌【真实邮件发信失败！】原因: %v", err)
	} else {
		log.Printf("✅【真实邮件发送成功！】请去邮箱查看。")
	}


	msg := "验证码已发送，请查收邮件"
	if isEn { msg = "Verification code sent, please check your email" }
	replyJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "msg": msg})
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		replyJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"ok": false})
		return
	}

	// ⚠️ 自动判定当前请求的语言环境
	isEn := !strings.Contains(strings.ToLower(r.Header.Get("Accept-Language")), "zh")

	bodyBytes, _ := io.ReadAll(r.Body)
	var reqData map[string]string
	json.Unmarshal(bodyBytes, &reqData)
	email := strings.ToLower(strings.TrimSpace(reqData["email"]))
	code := strings.TrimSpace(reqData["code"])

	if !regexp.MustCompile(`^\d{6}$`).MatchString(code) {
		msg := "验证码格式错误"
		if isEn { msg = "Invalid verification code format" }
		replyJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "msg": msg})
		return
	}

	tryCount := 0
	if val, ok := tryStore.Load(email); ok {
		tryCount = val.(int) + 1
	} else {
		tryCount = 1
	}
	tryStore.Store(email, tryCount)

	if tryCount > 5 {
		codesStore.Delete(email)
		msg := "错误次数过多，验证码已失效，请重新获取"
		if isEn { msg = "Too many failed attempts. Code invalidated, please get a new one" }
		replyJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "msg": msg})
		return
	}

	val, found := codesStore.Load(email)
	if !found {
		msg := "验证码错误或已过期"
		if isEn { msg = "Invalid or expired verification code" }
		replyJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "msg": msg})
		return
	}

	record := val.(codeRecord)
	if time.Now().After(record.ExpiresAt) || record.Code != code {
		msg := "验证码错误或已过期"
		if isEn { msg = "Invalid or expired verification code" }
		replyJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "msg": msg})
		return
	}

	codesStore.Delete(email)
	tryStore.Delete(email)

	token := generateSecureToken()
	sessionsStore.Store(token, sessionRecord{
		Email:     email,
		ExpiresAt: time.Now().Add(time.Duration(cfg.Auth.SessionTTL) * time.Second),
	})

	authCookie := &http.Cookie{
		Name:     cfg.Server.CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(cfg.Auth.SessionTTL),
	}

	if cfg.Server.CookieDomain != "" {
		authCookie.Domain = cfg.Server.CookieDomain
	}

	http.SetCookie(w, authCookie)
	replyJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}


func loadConfig(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("无法读取配置文件 config.yaml: %v", err)
	}
	defer file.Close()
	if err := yaml.NewDecoder(file).Decode(&cfg); err != nil {
		log.Fatalf("解析配置文件失败: %v", err)
	}
}

func validateSession(token string, w http.ResponseWriter) bool {
	val, found := sessionsStore.Load(token)
	if !found {
		return false
	}
	record := val.(sessionRecord)
	now := time.Now()

	if now.After(record.ExpiresAt) {
		sessionsStore.Delete(token)
		return false
	}

	remainingSeconds := int64(record.ExpiresAt.Sub(now).Seconds())

	// 当剩余时间少于配置的触发阈值线时，执行“双向无感平滑续期”
	if remainingSeconds < cfg.Auth.RenewTriggerTTL {
		// ⚠️ 核心微调：续期时，不仅延长 ExpiresAt，也会自动刷新其最近续期和状态基准线
		record.ExpiresAt = now.Add(time.Duration(cfg.Auth.SessionTTL) * time.Second)
		sessionsStore.Store(token, record) // 写入内存库同步

		renewCookie := &http.Cookie{
			Name:     cfg.Server.CookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   int(cfg.Auth.SessionTTL),
		}
		if cfg.Server.CookieDomain != "" {
			renewCookie.Domain = cfg.Server.CookieDomain
		}
		http.SetCookie(w, renewCookie)
		log.Printf("🔄 [网关智能续期] 用户 %s 活跃触发，状态延长至满额时长！", record.Email)
	}

return true
}

// ⚠️ 多接收一个 isEn 参数，用于判断是否投递英文邮件
func sendMail(to, code string, isEn bool) error {
	addr := fmt.Sprintf("%s:%s", cfg.Smtp.Host, cfg.Smtp.Port)
	var client *smtp.Client
	var err error
	if cfg.Smtp.SslEnabled {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         cfg.Smtp.Host,
		}
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("TLS 纯加密拨号失败: %v", err)
		}
		client, err = smtp.NewClient(conn, cfg.Smtp.Host)
		if err != nil {
			conn.Close()
			return fmt.Errorf("建立加密 SMTP 客户端失败: %v", err)
		}
	} else {
		client, err = smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("普通明文 TCP 拨号连接失败: %v", err)
		}
		if ok, _ := client.Extension("STARTTLS"); ok {
			config := &tls.Config{ServerName: cfg.Smtp.Host}
			if err = client.StartTLS(config); err != nil {
				client.Close()
				return fmt.Errorf("明文链路升级 STARTTLS 加密失败: %v", err)
			}
		}
	}
	defer client.Quit()
	auth := smtp.PlainAuth("", cfg.Smtp.User, cfg.Smtp.Pass, cfg.Smtp.Host)
	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP 发信身份认证拒绝: %v", err)
	}
	if err = client.Mail(cfg.Smtp.User); err != nil {
		return err
	}
	if err = client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}

	// 💡 动态拼装符合国际化标准的邮件头与正文
	subject := "【系统安全认证】登录验证码"
	body := "您好，您的验证码是 " + code + "，5 分钟内有效。若非本人操作请忽略。"
	if isEn {
		subject = "[Secure Auth] Verification Code"
		body = "Hello, your verification code is " + code + ". It is valid for 5 minutes. Please ignore this email if it was not requested by you."
	}

	msg := []byte("To: " + to + "\r\n" +
		"From: " + cfg.Smtp.User + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		body)

	_, err = w.Write(msg)
	if err != nil {
		return err
	}
	return w.Close()
}



func generateRandomCode() string {
var code string
for i := 0; i < 6; i++ {
num, _ := rand.Int(rand.Reader, big.NewInt(10))
code += fmt.Sprintf("%d", num)
}
return code
}
func generateSecureToken() string {
b := make([]byte, 32)
rand.Read(b)
return hex.EncodeToString(b)
}
func getRemoteIP(r *http.Request) string {
if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
parts := strings.Split(xff, ",")
if len(parts) > 0 {
return strings.TrimSpace(parts[0])
}
}
if xri := r.Header.Get("X-Real-IP"); xri != "" {
return xri
}
idx := strings.LastIndex(r.RemoteAddr, ":")
if idx != -1 {
return r.RemoteAddr[:idx]
}
return r.RemoteAddr
}
func replyJSON(w http.ResponseWriter, status int, data interface{}) {
w.Header().Set("Content-Type", "application/json; charset=utf-8")
w.Header().Set("Cache-Control", "no-store")
w.WriteHeader(status)
json.NewEncoder(w).Encode(data)
}
func startMemoryCleaner() {
ticker := time.NewTicker(10 * time.Second)
for range ticker.C {
now := time.Now()
codesStore.Range(func(k, v interface{}) bool {
if now.After(v.(codeRecord).ExpiresAt) {
codesStore.Delete(k)
}
return true
})
sessionsStore.Range(func(k, v interface{}) bool {
if now.After(v.(sessionRecord).ExpiresAt) {
sessionsStore.Delete(k)
}
return true
})
ipLimitStore.Range(func(k, v interface{}) bool {
if now.After(v.(rateLimitRecord).ExpiresAt) {
ipLimitStore.Delete(k)
}
return true
})
}
}

func serveVerifyPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	
	target := r.URL.Query().Get("target")
	if target == "" {
		target = "/"
	}

	htmlContent := `<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title id="title">安全验证</title>
<style>body{font-family:sans-serif;margin:0;padding:24px;background:#f5f6f8}
.c{max-width:360px;margin:60px auto;background:#fff;border-radius:12px;padding:24px;box-shadow:0 4px 12px rgba(0,0,0,0.05)}
h3{margin-top:0;color:#333;text-align:center}
input,button{width:100%;box-sizing:border-box;padding:12px;margin:8px 0;font-size:16px;border-radius:8px;border:1px solid #ccc;outline:none}
input:focus{border-color:#1677ff}
button{background:#1677ff;color:#fff;border:0;cursor:pointer;font-weight:500}
#m{color:#e64343;min-height:20px;font-size:14px;text-align:center;margin-top:4px}
button:disabled{background:#c8c9cc;color:#fff;cursor:not-allowed}
</style></head>
<body><div class="c"><h3 id="h3">安全接入认证</h3>
<input id="e" type="email" placeholder="请输入公司邮箱">
<button id="s">获取验证码</button>
<input id="k" inputmode="numeric" maxlength="6" placeholder="请输入6位验证码">
<button id="v">验证并登录</button><div id="m"></div></div>
<script>
var $=function(i){return document.getElementById(i)};
var e=$("e"),s=$("s"),k=$("k"),v=$("v"),m=$("m"),KEY="auth_until",COOL=60,timer=null;
var targetPath = {{.TargetPath}};

// ⚠️ 核心语言字典包
var i18n = {
    zh: { title: "安全验证", h3: "安全接入认证", email: "请输入公司邮箱", getCode: "获取验证码", code: "请输入6位验证码", login: "验证并登录", sending: "发送中...", resend: " 秒后可重发", netErr: "网络异常，请重试", success: "验证成功，正在跳转..." },
    en: { title: "Secure Verify", h3: "Secure Access Authentication", email: "Enter company email", getCode: "Get Code", code: "Enter 6-digit code", login: "Verify & Login", sending: "Sending...", resend: "s to resend", netErr: "Network error, retry later", success: "Success, redirecting..." }
};
// 自动判定浏览器语种
var lang = navigator.language.startsWith("zh") ? "zh" : "en";
var t = i18n[lang];

// 动态初始化界面语言
document.title = t.title; $("h3").textContent = t.h3; e.placeholder = t.email; k.placeholder = t.code; v.textContent = t.login;

function post(u,d){return fetch(u,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(d)}).then(function(r){return r.json()})}
function getU(){try{return parseInt(localStorage.getItem(KEY)||"0",10)}catch(x){return 0}}
function setU(t){try{localStorage.setItem(KEY,String(t))}catch(x){}}
function left(){return Math.max(0,Math.ceil((getU()-Date.now())/1000))}
function okEmail(){return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e.value.trim())}
function renderS(){
 var n=left();
 if(n>0){s.disabled=true;s.textContent=n + t.resend;return}
 if(timer){clearInterval(timer);timer=null}
 s.textContent=t.getCode;s.disabled=!okEmail();
}
function renderV(){v.disabled=!(okEmail()&&/^\d{6}$/.test(k.value))}
function startCool(){setU(Date.now()+COOL*1000);renderS();if(!timer)timer=setInterval(renderS,500)}
e.oninput=function(){if(left()===0)renderS();renderV()};
k.oninput=function(){k.value=k.value.replace(/\D/g,"");renderV()};
s.onclick=function(){
 if(s.disabled)return;
 s.disabled=true;s.textContent=t.sending;m.textContent="";
 post("/auth/send",{email:e.value.trim()}).then(function(j){
  m.textContent=j.msg||"";
  if(j.ok){startCool()}else{renderS()}
 }).catch(function(){m.textContent=t.netErr;renderS()});
};
v.onclick=function(){
 if(v.disabled)return;
 v.disabled=true;v.textContent=t.sending;m.textContent="";
 post("/auth/verify",{email:e.value.trim(),code:k.value}).then(function(j){
  if(j.ok){m.style.color="#09bb07";m.textContent=t.success;setTimeout(function(){location.replace(targetPath)},800)}
  else{m.style.color="#e64343";m.textContent=j.msg||"Error";v.textContent=t.login;renderV()}
 }).catch(function(){m.textContent=t.netErr;v.textContent=t.login;renderV()});
};
renderS();renderV();
if(left()>0)timer=setInterval(renderS,500);
</script></body></html>`

	t, err := template.New("webpage").Parse(htmlContent)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	t.Execute(w, map[string]interface{}{"TargetPath": target})
}


// 检查当前访问者是否具有管理员身份的通用安全防线
func checkAdminAuth(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie(cfg.Server.CookieName)
	if err != nil {
		http.Error(w, "未检测到有效会话，拒绝访问 (401 Unauthorized)", http.StatusUnauthorized)
		return false
	}
	val, found := sessionsStore.Load(cookie.Value)
	if !found {
		http.Error(w, "登录状态已失效，请重新登录", http.StatusUnauthorized)
		return false
	}
	email := strings.ToLower(val.(sessionRecord).Email)
	if !adminMap[email] {
		http.Error(w, fmt.Sprintf("⚠️ 安全鉴权拒绝: 您的账号 [%s] 不是系统登记的管理员，无权查看审计面板！", email), http.StatusForbidden)
		return false
	}
	return true
}

// 1. 会话列表数据源 API
func handleSessionListAPI(w http.ResponseWriter, r *http.Request) {
	if !checkAdminAuth(w, r) { return }

	// ⚠️ 显式通过 json 标签指定小写键名，完全对齐前端
	type SessionItem struct {
		TokenKey     string `json:"token_key"`
		TokenPrefix  string `json:"token_prefix"`
		Email        string `json:"email"`
		IP           string `json:"ip"`
		AuthType     string `json:"auth_type"`     // 原本的 授权类型
		LoginTime    string `json:"login_time"`    // 原本的 登录时间
		RenewTime    string `json:"renew_time"`    // 原本的 最近续期
		ExpiresAt    string `json:"expires_at"`    // 对应 剩余生命周期计算基准
		RemainingStr string `json:"remaining_str"` // 原本的 剩余有效期文字 (如: X小时X分X秒)
	}

	var list []SessionItem
	now := time.Now()

	sessionsStore.Range(func(key, value interface{}) bool {
		token := key.(string)
		record := value.(sessionRecord)
		if now.Before(record.ExpiresAt) {
			prefix := token[:6] + "..."
			
			// 1. 计算原本样式的精确剩余时间文字
			dur := record.ExpiresAt.Sub(now)
			hours := int(dur.Hours())
			minutes := int(dur.Minutes()) % 60
			seconds := int(dur.Seconds()) % 60
			remainingStr := fmt.Sprintf("%d小时%d分%d秒", hours, minutes, seconds)

			// 2. 格式化为你原本 OpenResty 的短日期格式 (如 10/29 \n 17:12:25)
			// 注意：因为 Go 网关采用单点内存 Session，最近续期和登录时间默认保持一致，续期时会自动更新
			loginTimeStr := record.ExpiresAt.Add(-time.Duration(cfg.Auth.SessionTTL)*time.Second).Format("01/02 15:04:05")
			renewTimeStr := record.ExpiresAt.Add(-time.Duration(cfg.Auth.SessionTTL)*time.Second).Format("01/02 15:04:05")

			authTypeLabel := "User"
			isAdmin := adminMap[strings.ToLower(record.Email)]
			
			// 检查当前看监控的管理员浏览器是不是中文环境
			if strings.Contains(strings.ToLower(r.Header.Get("Accept-Language")), "zh") {
				if isAdmin {
					authTypeLabel = "管理员"
				} else {
					authTypeLabel = "用户"
				}
			} else {
				if isAdmin {
					authTypeLabel = "Admin"
				}
			}
			list = append(list, SessionItem{
				TokenKey:     token,
				TokenPrefix:  prefix,
				Email:        record.Email,
				IP:           getRemoteIP(r), 
				AuthType:     authTypeLabel, // 默认赋予正式标签，对齐原本样式
				LoginTime:    loginTimeStr,
				RenewTime:    renewTimeStr,
				ExpiresAt:    record.ExpiresAt.Format("01/02 15:04:05"),
				RemainingStr: remainingStr,
			})
		}
		return true
	})

	replyJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "data": list})
}


// 2. 强行踢人下线（删除内存 Session）API
func handleKickSessionAPI(w http.ResponseWriter, r *http.Request) {
	if !checkAdminAuth(w, r) { return }
	
	r.ParseForm()
	bodyBytes, _ := io.ReadAll(r.Body)
	var reqData map[string]string
	json.Unmarshal(bodyBytes, &reqData)
	targetToken := reqData["token_key"]

	if targetToken != "" {
		sessionsStore.Delete(targetToken) // 👈 内存抹除，该用户下一次点击任何页面瞬间被网关无情拦截！
		replyJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "msg": "已强制该用户下线"})
		return
	}
	replyJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "msg": "无效参数"})
}

// 3. 完美内嵌你发给我的那个现代版“会话监控网页面板”
func handleMonitorPage(w http.ResponseWriter, r *http.Request) {
	if !checkAdminAuth(w, r) { return }

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	htmlContent := `<!DOCTYPE html><html><head><meta charset="utf-8">
<title id="title">会话监控 · ZTA网络</title>
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;padding:20px;background:#f4f6f9;color:#333}
.container{max-width:1100px;margin:20px auto;background:#fff;border-radius:8px;padding:24px;box-shadow:0 2px 10px rgba(0,0,0,0.05)}
.header{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #eaeaea;padding-bottom:12px;margin-bottom:20px}
h2{margin:0;color:#1a1a1a;font-size:20px}
.btn{background:#1677ff;color:#fff;border:0;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:14px;font-weight:500}
.btn:hover{background:#0050b3}.btn-danger{background:#ff4d4f}
.btn-danger:hover{background:#cf1322}
table{width:100%;border-collapse:collapse;margin-top:10px}
th,td{text-align:left;padding:14px 12px;border-bottom:1px solid #f0f0f0;font-size:14px;vertical-align:middle}
th{background:#fafafa;color:#555;font-weight:600;user-select:none}
.empty{text-align:center;padding:40px;color:#999;font-size:14px}
.tag-user{background:#e6f7ff;color:#1677ff;border:1px solid #91d5ff;padding:4px 8px;border-radius:4px;font-size:12px;font-weight:500}
.tag-admin{background:#fff7e6;color:#fa8c16;border:1px solid #ffd591;padding:4px 8px;border-radius:4px;font-size:12px;font-weight:500}
.progress-line{display:inline-block;width:40px;height:4px;background:#52c41a;border-radius:2px;margin-right:8px;vertical-align:middle}
.time-box{white-space:pre-line;line-height:1.4;color:#555}
.token-txt{font-family:monospace;color:#888}
.kick-icon{cursor:pointer;padding:6px;border-radius:4px;border:1px solid #d9d9d9;background:#fff;color:#555;font-size:12px}
.kick-icon:hover{color:#ff4d4f;border-color:#ff4d4f;background:#fff1f0}
</style></head>
<body>
<div class="container">
 <div class="header">
  <h2 id="h2">会话监控中心 · ZTA网络</h2>
  <button class="btn" id="refreshBtn" onclick="loadSessions()">立即刷新</button>
 </div>
 <table>
  <thead id="thead">
   <!-- 动态渲染表头 -->
  </thead>
  <tbody id="box"><tr><td colspan="8" class="empty" id="loadingTxt">正在加载活跃会话列表...</td></tr></tbody>
 </table>
</div>
<script>
var baseAPI = "REPLACE_ME_BASE_API_PATH"; 

// ⚠️ 管理面板多语言国际化字典
var i18n = {
    zh: { title: "会话监控 · ZTA网络", h2: "会话监控中心 · ZTA网络", refresh: "立即刷新", loading: "正在加载活跃会话列表...", empty: "当前系统内没有活跃的在线会话", ths: ["用户","来源IP","身份类型","登录时间","最近续期","剩余有效期","Token前缀","操作"], kickBtn: "踢", confirmKick: "确定要强行终止该用户的会话并踢其下线吗？", minute: " 分钟" },
    en: { title: "Session Monitor · ZTA", h2: "Session Monitor Center", refresh: "Refresh", loading: "Loading active sessions...", empty: "No active sessions found", ths: ["User","Source IP","Role","Login Time","Last Renew","Remaining TTL","Prefix","Action"], kickBtn: "Kick", confirmKick: "Are you sure you want to force terminate this user's session?", minute: " min" }
};
var lang = navigator.language.startsWith("zh") ? "zh" : "en";
var t = i18n[lang];

// 初始化文本
document.title = t.title; document.getElementById("h2").textContent = t.h2; document.getElementById("refreshBtn").textContent = t.refresh; document.getElementById("loadingTxt").textContent = t.loading;

// 初始化表头
var thHtml = "<tr>"; t.ths.forEach(function(th){ thHtml += "<th>"+th+"</th>"; }); thHtml += "</tr>";
document.getElementById("thead").innerHTML = thHtml;

function formatTime(str) {
    if(!str) return "";
    var parts = str.split(" ");
    if(parts.length < 2) return str;
    return "<div class='time-box'>" + parts[0] + "<br>" + parts[1] + "</div>";
}

function loadSessions(){
 fetch(baseAPI + '/list').then(r=>r.json()).then(j=>{
  var box = document.getElementById("box");
  if(!j.data || j.data.length===0){
   box.innerHTML = '<tr><td colspan="8" class="empty">' + t.empty + '</td></tr>';
   return;
  }
  var html = "";
  j.data.forEach(item=>{
   var tagClass = (item.auth_type === "管理员" || item.auth_type === "Admin") ? "tag-admin" : "tag-user";
   
   // 动态处理剩余时间的英文显示单位
   var rTime = item.remaining_str;
   if(lang === "en") {
       // 将“X小时X分X秒”简易转换为带有英文含义的文本或直接展示秒数计算值
       var min = Math.ceil(item.remaining_seconds / 60);
       rTime = min + t.minute;
   }

   html += "<tr>"+
    "<td>" + item.email + "</td>"+
    "<td><span style='color:#888'>" + item.ip + "</span></td>"+
    "<td><span class='" + tagClass + "'>" + item.auth_type + "</span></td>"+
    "<td>" + formatTime(item.login_time) + "</td>"+
    "<td>" + formatTime(item.renew_time) + "</td>"+
    "<td><span class='progress-line'></span>" + rTime + "</td>"+
    "<td><span class='token-txt'>" + item.token_prefix + "</span></td>"+
    "<td><button class='kick-icon' onclick='kick(\"" + item.token_key + "\")'>" + t.kickBtn + "</button></td>"+
   "</tr>";
  });
  box.innerHTML = html;
 });
}
function kick(token){
 if(!confirm(t.confirmKick)) return;
 fetch(baseAPI + '/kick', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({token_key: token})
 }).then(r=>r.json()).then(j=>{
  loadSessions();
 });
}
loadSessions();
setInterval(loadSessions, 5000);
</script></body></html>`

	finalHTML := strings.ReplaceAll(htmlContent, "REPLACE_ME_BASE_API_PATH", "/auth/admin/api")
	fmt.Fprint(w, finalHTML)
}


