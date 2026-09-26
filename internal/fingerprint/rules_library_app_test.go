package fingerprint

import (
	"net/http"
	"strings"
	"testing"

	"westy_scan/internal/model"
)

// appRuleCase 是"应用层规则库"的一条正样本：
// asset + headers + body 构成一个该产品的真实风格响应，want 是期望被命中的产品名。
//
// extra 是本样本**允许**额外命中的产品：真实响应本来就会同时命中产品与它的父类规则
// （例如 Apache Tomcat/9.0.83 会同时命中内置的 "Apache Tomcat" 与新增的 "Tomcat 9"），
// 这类"同族叠加"不是误报；除 extra 之外的任何命中都算交叉误报。
type appRuleCase struct {
	name    string
	want    string
	extra   []string
	asset   model.Asset
	headers http.Header
	body    string
}

// hdr 是构造 http.Header 的语法糖。
func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

// appRuleCases 返回全部正样本。每条新增规则至少一个样本；
// TestLibraryAppRulesMatchSamples 与 TestLibraryAppRulesNoCollision 共用。
func appRuleCases() []appRuleCase {
	return []appRuleCase{
		// ---------------- Web 服务器 / 中间件 ----------------
		{
			name: "Tomcat 9 版本页", want: "Tomcat 9", extra: []string{"Apache Tomcat"},
			asset: model.Asset{Host: "h", Port: 8080},
			body:  `<html><head><title>Apache Tomcat/9.0.83</title></head><body><h1>Apache Tomcat/9.0.83</h1></body></html>`,
		},
		{
			name: "Tomcat 10 版本页", want: "Tomcat 10", extra: []string{"Apache Tomcat"},
			asset: model.Asset{Host: "h", Port: 8080},
			body:  `<html><head><title>Apache Tomcat/10.1.24</title></head><body>Apache Tomcat/10.1.24</body></html>`,
		},
		{
			name: "Tomcat 8 版本页", want: "Tomcat 8", extra: []string{"Apache Tomcat"},
			asset: model.Asset{Host: "h", Port: 8080},
			body:  `<html><head><title>Apache Tomcat/8.5.100</title></head><body>Apache Tomcat/8.5.100</body></html>`,
		},
		{
			name: "Apache-Coyote 默认页", want: "Tomcat 9", extra: []string{"Apache Tomcat", "Apache httpd"},
			asset:   model.Asset{Host: "h", Port: 8080},
			headers: hdr("Server", "Apache-Coyote/1.1"),
			body:    `<html><head><title>Apache Tomcat/9.0.83</title></head><body><h1>HTTP Status 404 – Not Found</h1><p>Apache Tomcat/9.0.83</p></body></html>`,
		},
		{
			name: "Jetty Server 头", want: "Jetty",
			asset:   model.Asset{Host: "h", Port: 8080, Title: "Error 404"},
			headers: hdr("Server", "Jetty(9.4.53.v20231009)"),
			body:    `<html><head><title>Error 404</title></head><body><h2>HTTP ERROR 404 Not Found</h2><hr><i>Powered by Jetty:// 9.4.53.v20231009</i></body></html>`,
		},
		{
			name: "WildFly 欢迎页", want: "WildFly",
			asset:   model.Asset{Host: "h", Port: 8080, Title: "WildFly 30"},
			headers: hdr("Server", "WildFly/30.0.0.Final"),
			body:    `<html><head><title>WildFly 30</title></head><body><h1>Welcome to WildFly</h1><p>Your WildFly 30 is running.</p></body></html>`,
		},
		{
			name: "JBoss EAP 欢迎页", want: "JBoss",
			asset:   model.Asset{Host: "h", Port: 8080, Title: "Welcome to JBoss EAP 7"},
			headers: hdr("Server", "JBoss-EAP/7"),
			body:    `<html><head><title>Welcome to JBoss EAP 7</title></head><body><h1>Welcome to JBoss&trade;</h1><p>jboss.web</p></body></html>`,
		},
		{
			name: "WebSphere 控制台", want: "WebSphere",
			asset:   model.Asset{Host: "h", Port: 9043, Title: "WebSphere Integrated Solutions Console"},
			headers: hdr("Server", "WebSphere Application Server/9.0"),
			body:    `<html><head><title>WebSphere Integrated Solutions Console</title></head><body>IBM WebSphere Application Server</body></html>`,
		},
		{
			name: "GlassFish 管理控制台", want: "GlassFish",
			asset:   model.Asset{Host: "h", Port: 4848, Title: "GlassFish Server 5.1"},
			headers: hdr("Server", "GlassFish Server Open Source Edition 5.1"),
			body:    `<html><head><title>GlassFish Server 5.1</title></head><body><p>GlassFish Server Open Source Edition</p></body></html>`,
		},
		{
			name: "Resin 默认页", want: "Resin",
			asset:   model.Asset{Host: "h", Port: 8080, Title: "Resin"},
			headers: hdr("Server", "Resin/4.0.65"),
			body:    `<html><head><title>Resin</title></head><body><h1>Resin Default Home Page</h1><p>Quercus</p></body></html>`,
		},
		{
			name: "Undertow 错误页", want: "Undertow",
			asset:   model.Asset{Host: "h", Port: 8080},
			headers: hdr("Server", "undertow"),
			body:    `<html><head><title>Error</title></head><body><h1>HTTP Status 404 – Not Found</h1></body></html>`,
		},
		{
			name: "Caddy Server 头", want: "Caddy",
			asset:   model.Asset{Host: "h", Port: 443},
			headers: hdr("Server", "Caddy"),
			body:    `<!DOCTYPE html><html><head><title>Hello</title></head><body>hi</body></html>`,
		},
		{
			name: "Lighttpd 404 页", want: "Lighttpd",
			asset:   model.Asset{Host: "h", Port: 80, Title: "404 - Not Found"},
			headers: hdr("Server", "lighttpd/1.4.73"),
			body:    `<html><head><title>404 - Not Found</title></head><body><h2>404 - Not Found</h2></body></html>`,
		},
		{
			name: "Microsoft IIS 6.0", want: "Microsoft IIS 6.0", extra: []string{"Microsoft IIS"},
			asset:   model.Asset{Host: "h", Port: 80},
			headers: hdr("Server", "Microsoft-IIS/6.0"),
		},
		{
			name: "Microsoft IIS 7.5", want: "Microsoft IIS 7.5", extra: []string{"Microsoft IIS"},
			asset:   model.Asset{Host: "h", Port: 80, Title: "IIS Windows Server"},
			headers: hdr("Server", "Microsoft-IIS/7.5"),
			body:    `<html><head><title>IIS Windows Server</title></head><body></body></html>`,
		},
		{
			name: "Microsoft IIS 10.0", want: "Microsoft IIS 10.0", extra: []string{"Microsoft IIS"},
			asset:   model.Asset{Host: "h", Port: 80},
			headers: hdr("Server", "Microsoft-IIS/10.0"),
		},
		{
			name: "Tengine Server 头", want: "Tengine",
			asset:   model.Asset{Host: "h", Port: 80, Title: "Welcome to tengine!"},
			headers: hdr("Server", "Tengine/2.3.3"),
			body:    `<html><head><title>Welcome to tengine!</title></head><body>Thank you for using tengine.</body></html>`,
		},
		{
			name: "Nginx Unit 控制 API", want: "Nginx Unit",
			asset:   model.Asset{Host: "h", Port: 8443},
			headers: hdr("Server", "unit/1.31.1"),
			body:    `{"unit":{"version":"1.31.1"},"listeners":{"*:8080":{"pass":"applications/myapp"}},"applications":{"myapp":{"type":"php"}}}`,
		},

		// ---------------- Java 生态 / 框架 ----------------
		{
			name: "Shiro rememberMe Cookie", want: "Apache Shiro",
			asset:   model.Asset{Host: "h", Port: 8080},
			headers: hdr("Set-Cookie", "rememberMe=deleteMe; Path=/; Max-Age=0"),
		},
		{
			name: "Struts2 .action 链接", want: "Apache Struts2",
			asset: model.Asset{Host: "h", Port: 8080},
			body:  `<html><body><a href="login.action">登录</a><form action="/user/list.action" method="post"></form></body></html>`,
		},
		{
			name: "Spring Cloud Gateway 报错", want: "Spring Cloud Gateway",
			asset: model.Asset{Host: "h", Port: 8080},
			body:  `{"timestamp":"2024-05-01T10:00:00.000+00:00","path":"/demo","status":404,"error":"Not Found","message":"No matching handler route for Spring Cloud Gateway request"}`,
		},
		{
			name: "Spring Security 默认登录页", want: "Spring Security",
			asset: model.Asset{Host: "h", Port: 8080, Title: "Please sign in"},
			body:  `<html><head><title>Please sign in</title></head><body><form action="/login" method="post"><input name="username"><input name="password"><button>Sign in</button></form></body></html>`,
		},
		{
			name: "Fastjson 解析异常", want: "Fastjson",
			asset: model.Asset{Host: "h", Port: 8080},
			body:  `{"error":"com.alibaba.fastjson.JSONException: syntax error, expect {, actual error"}`,
		},
		{
			name: "Druid 监控页", want: "Druid Monitor",
			asset: model.Asset{Host: "h", Port: 8080, Title: "Druid Stat Index"},
			body:  `<html><head><title>Druid Stat Index</title></head><body><script src="druid.js"></script><div id="druid">Druid Stat Index</div></body></html>`,
		},
		{
			name: "Swagger UI 页面", want: "Swagger UI",
			asset: model.Asset{Host: "h", Port: 8080, Title: "Swagger UI"},
			body:  `<html><head><title>Swagger UI</title><link rel="stylesheet" href="./swagger-ui.css"></head><body><div id="swagger-ui"></div><script src="./swagger-ui-bundle.js"></script><script src="./swagger-ui-standalone-preset.js"></script></body></html>`,
		},
		{
			name: "Apollo Server 报错", want: "Apollo GraphQL",
			asset: model.Asset{Host: "h", Port: 8080},
			body:  "{\"errors\":[{\"message\":\"GraphQL operations must contain a non-empty `query` or a `persistedQuery` extension.\",\"extensions\":{\"code\":\"INTERNAL_SERVER_ERROR\"}}]}",
		},
		{
			name: "GraphQL Playground 页面", want: "GraphQL Playground",
			asset: model.Asset{Host: "h", Port: 8080, Title: "GraphQL Playground"},
			body:  `<html><head><title>GraphQL Playground</title></head><body><div id="root"></div><script src="/graphql-playground-react/static/js/middleware.js"></script></body></html>`,
		},
		{
			name: "Spring Actuator 根端点", want: "Spring Actuator",
			asset: model.Asset{Host: "h", Port: 8080},
			body:  `{"_links":{"self":{"href":"http://localhost:8080/actuator","templated":false},"health":{"href":"http://localhost:8080/actuator/health"}}}`,
		},
		{
			name: "Jenkins 会话头", want: "Jenkins API", extra: []string{"Jenkins"},
			asset:   model.Asset{Host: "h", Port: 8080, Title: "Dashboard [Jenkins]"},
			headers: hdr("X-Jenkins", "2.440.1", "X-Jenkins-Session", "cd1f8d3a"),
			body:    `<html><head><title>Dashboard [Jenkins]</title></head><body>jenkins</body></html>`,
		},

		// ---------------- 语言 / 框架 ----------------
		{
			name: "Django CSRF Cookie", want: "Django",
			asset:   model.Asset{Host: "h", Port: 8000, Title: "Django: the web framework"},
			headers: hdr("Set-Cookie", "csrftoken=abc123def456; expires=Wed, 01 Jan 2025 00:00:00 GMT; Path=/"),
			body:    `<html><body><form method="post"><input type="hidden" name="csrfmiddlewaretoken" value="abc123"></form></body></html>`,
		},
		{
			name: "Django CSRF 校验失败页", want: "Django",
			asset: model.Asset{Host: "h", Port: 8000, Title: "403 Forbidden"},
			body:  `<html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>CSRF verification failed. Request aborted.</p></body></html>`,
		},
		{
			name: "Flask Werkzeug Server 头", want: "Flask",
			asset:   model.Asset{Host: "h", Port: 5000, Title: "Home"},
			headers: hdr("Server", "Werkzeug/3.0.1 Python/3.11.6"),
			body:    `<html><head><title>Home</title></head><body>hello</body></html>`,
		},
		{
			name: "Express X-Powered-By", want: "Express",
			asset:   model.Asset{Host: "h", Port: 3000, Title: "Express"},
			headers: hdr("X-Powered-By", "Express"),
			body:    `<html><head><title>Express</title></head><body><h1>Welcome to Express</h1></body></html>`,
		},
		{
			name: "NestJS X-Powered-By", want: "NestJS",
			asset:   model.Asset{Host: "h", Port: 3000},
			headers: hdr("X-Powered-By", "NestJS"),
			body:    `<html><body><h1>Cannot GET /</h1><p>nestjs</p></body></html>`,
		},
		{
			name: "Laravel 会话 Cookie", want: "Laravel",
			asset:   model.Asset{Host: "h", Port: 80, Title: "Laravel"},
			headers: hdr("Set-Cookie", "laravel_session=eyJpdiI6Ik1UZz0iLCJ2YWx1ZSI6IkFCQyJ9; expires=Wed, 01 Jan 2025 00:00:00 GMT; path=/; httponly"),
			body:    `<html><head><title>Laravel</title></head><body>Laravel</body></html>`,
		},
		{
			name: "Rails X-Runtime 头", want: "Ruby on Rails",
			asset:   model.Asset{Host: "h", Port: 3000, Title: "Ruby on Rails: Welcome aboard"},
			headers: hdr("X-Runtime", "0.012345", "X-Powered-By", "Phusion Passenger 6.0.18"),
			body:    `<html><head><title>Ruby on Rails: Welcome aboard</title></head><body><h1>Ruby on Rails</h1></body></html>`,
		},
		{
			name: "Next.js __NEXT_DATA__", want: "Next.js",
			asset:   model.Asset{Host: "h", Port: 3000, Title: "Next.js App"},
			headers: hdr("X-Powered-By", "Next.js"),
			body:    `<html><body><script id="__NEXT_DATA__" type="application/json">{"props":{}}</script><script src="/_next/static/chunks/main.js"></script></body></html>`,
		},
		{
			name: "Nuxt __NUXT__", want: "Nuxt",
			asset: model.Asset{Host: "h", Port: 3000, Title: "Nuxt App"},
			body:  `<html><body><script>window.__NUXT__={"data":[]}</script><script src="/_nuxt/runtime.js"></script></body></html>`,
		},
		{
			name: "Vue CLI dev server 页", want: "Vue CLI",
			asset: model.Asset{Host: "h", Port: 8080, Title: "my-app"},
			body:  `<html><body><div id="app"></div><script src="/js/chunk-vendors.js"></script><div class="vue-cli-plugin">@vue/cli 5.0.8</div></body></html>`,
		},
		{
			name: "Vite dev server 页", want: "Vite Dev Server",
			asset: model.Asset{Host: "h", Port: 5173, Title: "Vite + Vue"},
			body:  `<html><head><title>Vite + Vue</title></head><body><div id="app"></div><script type="module" src="/@vite/client"></script><script type="module" src="/src/main.js"></script></body></html>`,
		},

		// ---------------- CMS / 建站 ----------------
		{
			name: "WordPress 站点", want: "WordPress",
			asset:   model.Asset{Host: "h", Port: 80, Title: "我的博客"},
			headers: hdr("X-Pingback", "http://h/xmlrpc.php", "Link", "<http://h/wp-json/>; rel=\"https://api.w.org/\""),
			body:    `<html><head><title>我的博客</title><meta name="generator" content="WordPress 6.5.2" /></head><body><link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css"><script src="/wp-includes/js/jquery/jquery.min.js"></script></body></html>`,
		},
		{
			name: "Drupal 站点", want: "Drupal",
			asset:   model.Asset{Host: "h", Port: 80, Title: "Welcome"},
			headers: hdr("X-Generator", "Drupal 10 (https://www.drupal.org)"),
			body:    `<html><head><title>Welcome</title></head><body><script src="/core/misc/drupal.js"></script><script>window.Drupal.settings = {"basePath":"/"};</script></body></html>`,
		},
		{
			name: "Joomla 站点", want: "Joomla",
			asset: model.Asset{Host: "h", Port: 80, Title: "Home"},
			body:  `<html><head><title>Home</title><meta name="generator" content="Joomla! - Open Source Content Management" /></head><body><link rel="stylesheet" href="/media/jui/css/bootstrap.min.css"><a href="/index.php?option=com_content&view=article">Article</a></body></html>`,
		},
		{
			name: "Typecho 博客", want: "Typecho",
			asset: model.Asset{Host: "h", Port: 80, Title: "Typecho Blog"},
			body:  `<html><head><title>Typecho Blog</title><meta name="generator" content="Typecho 1.2.1" /></head><body><link rel="stylesheet" href="/usr/themes/default/style.css"><a href="/index.php/archives/1/">归档</a></body></html>`,
		},
		{
			name: "Discuz 论坛", want: "Discuz",
			asset: model.Asset{Host: "h", Port: 80, Title: "Discuz! Board"},
			body:  `<html><head><title>Discuz! Board</title><meta name="generator" content="Discuz! X3.5" /></head><body><a href="forum.php?mod=forumdisplay&fid=2">版块</a><img src="/static/image/common/logo.png"></body></html>`,
		},
		{
			name: "PHPCMS 站点", want: "PHPCMS",
			asset: model.Asset{Host: "h", Port: 80, Title: "首页"},
			body:  `<html><head><title>首页</title><meta name="generator" content="PHPCMS V9" /></head><body><script src="/statics/js/jquery.min.js"></script><a href="/index.php?m=content&c=index&a=lists&catid=1">栏目</a></body></html>`,
		},
		{
			name: "DedeCMS 站点", want: "DedeCMS",
			asset: model.Asset{Host: "h", Port: 80, Title: "首页"},
			body:  `<html><head><title>首页</title></head><body><link rel="stylesheet" href="/templets/default/style/dedecms.css"><div>Power by DedeCms</div></body></html>`,
		},
		{
			name: "Ghost 博客", want: "Ghost",
			asset:   model.Asset{Host: "h", Port: 2368, Title: "Ghost"},
			headers: hdr("X-Powered-By", "Ghost 5.80"),
			body:    `<html><head><title>Ghost</title><meta name="generator" content="Ghost 5.80" /></head><body><script src="/assets/built/main.js"></script></body></html>`,
		},
		{
			name: "Halo 博客", want: "Halo",
			asset: model.Asset{Host: "h", Port: 8090, Title: "Halo"},
			body:  `<html><head><title>Halo</title></head><body><link rel="stylesheet" href="/themes/theme-anatole/assets/css/style.css"><script src="/api/content/posts"></script></body></html>`,
		},
		{
			name: "Hexo 博客", want: "Hexo",
			asset: model.Asset{Host: "h", Port: 4000, Title: "Hexo"},
			body:  `<html><head><title>Hexo</title><meta name="generator" content="Hexo 7.2.0" /></head><body><script src="/js/hexo.js"></script></body></html>`,
		},

		// ---------------- 数据库及其 Web 面板 ----------------
		{
			name: "ClickHouse HTTP 接口", want: "ClickHouse",
			asset:   model.Asset{Host: "h", Port: 8123},
			headers: hdr("X-ClickHouse-Server-Display-Name", "node-1"),
			body:    `Ok.`,
		},
		{
			name: "InfluxDB 版本头", want: "InfluxDB",
			asset:   model.Asset{Host: "h", Port: 8086},
			headers: hdr("X-Influxdb-Version", "1.8.10", "X-Influxdb-Build", "OSS"),
			body:    `{"name":"influxdb","message":"ready for queries and writes","status":"pass"}`,
		},
		{
			name: "CouchDB 欢迎 JSON", want: "CouchDB",
			asset: model.Asset{Host: "h", Port: 5984},
			body:  `{"couchdb":"Welcome","version":"3.3.2","vendor":{"name":"The Apache Software Foundation"}}`,
		},
		{
			name: "Cassandra 9042 banner", want: "Cassandra",
			asset: model.Asset{Host: "h", Port: 9042, Banner: "Cassandra native protocol v5 server"},
		},
		{
			name: "ZooKeeper stat 四字命令响应", want: "Apache ZooKeeper",
			asset: model.Asset{Host: "h", Port: 2181,
				Banner: "Zookeeper version: 3.8.4--1, built on 02/12/2024 06:23 GMT\nClients:"},
		},
		{
			name: "ZooKeeper ruok 响应", want: "Apache ZooKeeper",
			asset: model.Asset{Host: "h", Port: 2181, Banner: "imok"},
		},
		{
			name: "Oracle TNS 监听器描述", want: "Oracle TNS Listener",
			asset: model.Asset{Host: "h", Port: 1521,
				Banner: `(DESCRIPTION=(TMP=)(VSNNUM=354549760)(ERR=12514)(ERROR_STACK=(ERROR=(CODE=12514)(EMFI=4))))`},
		},
		{
			name: "MSSQL 1433 预登录 banner", want: "Microsoft SQL Server",
			asset: model.Asset{Host: "h", Port: 1433,
				Banner: "Microsoft SQL Server 2019 - 15.0.2000.5 (X64) Standard Edition"},
		},
		{
			name: "DB2 50000 banner", want: "IBM DB2",
			asset: model.Asset{Host: "h", Port: 50000,
				Banner: "IBM DB2 11.5.8 with SQL30081N communication error"},
		},
		{
			name: "Neo4j 7474 浏览器", want: "Neo4j",
			asset:   model.Asset{Host: "h", Port: 7474, Title: "Neo4j Browser"},
			headers: hdr("X-Neo4j-Version", "5.19.0", "X-Neo4j-Edition", "community"),
			body:    `<html><head><title>Neo4j Browser</title></head><body>{"neo4j_version":"5.19.0"}</body></html>`,
		},
		{
			name: "Prometheus 9090", want: "Prometheus",
			asset: model.Asset{Host: "h", Port: 9090, Title: "Prometheus"},
			body:  `<html><head><title>Prometheus</title></head><body>Prometheus Time Series Collection and Processing Server</body></html>`,
		},
		{
			name: "OpenTSDB 4242", want: "OpenTSDB",
			asset: model.Asset{Host: "h", Port: 4242, Title: "OpenTSDB"},
			body:  `<html><head><title>OpenTSDB</title></head><body><div class="opentsdb">OpenTSDB 2.4.1</div></body></html>`,
		},
		{
			name: "QuestDB 9000 控制台", want: "QuestDB",
			asset: model.Asset{Host: "h", Port: 9000, Title: "QuestDB Console"},
			body:  `<html><head><title>QuestDB Console</title><link rel="icon" href="/assets/questdb/favicon.ico"></head><body><div id="questdb">QuestDB</div></body></html>`,
		},
		{
			name: "TimescaleDB PostgreSQL banner", want: "TimescaleDB", extra: []string{"PostgreSQL"},
			asset: model.Asset{Host: "h", Port: 5432,
				Banner: "PostgreSQL 14.5 on x86_64-pc-linux-gnu, compiled by gcc, TimescaleDB 2.11.2"},
		},

		// ---------------- DevOps / CI / 制品库 ----------------
		{
			name: "SonarQube 页面", want: "SonarQube",
			asset:   model.Asset{Host: "h", Port: 9000, Title: "SonarQube"},
			headers: hdr("X-SonarQube-Version", "10.4.1"),
			body:    `<html><head><title>SonarQube</title></head><body><div id="content">SonarQube</div></body></html>`,
		},
		{
			name: "Nexus Repository Manager", want: "Sonatype Nexus",
			asset:   model.Asset{Host: "h", Port: 8081, Title: "Nexus Repository Manager"},
			headers: hdr("Server", "Nexus/3.68.0-04 (OSS)"),
			body:    `<html><head><title>Nexus Repository Manager</title></head><body>NXRM</body></html>`,
		},
		{
			name: "JFrog Artifactory", want: "JFrog Artifactory",
			asset:   model.Asset{Host: "h", Port: 8082, Title: "Artifactory"},
			headers: hdr("X-Artifactory-Id", "a0b1c2d3e4f5", "X-Artifactory-Node-Id", "node1"),
			body:    `<html><head><title>Artifactory</title></head><body>JFrog Artifactory 7.77.5</body></html>`,
		},
		{
			name: "Gitea 页面", want: "Gitea",
			asset:   model.Asset{Host: "h", Port: 3000, Title: "Gitea: Git with a cup of tea"},
			headers: hdr("Set-Cookie", "i_like_gitea=abc123; Path=/; HttpOnly"),
			body:    `<html><head><title>Gitea: Git with a cup of tea</title></head><body><div class="footer">Powered by Gitea</div></body></html>`,
		},
		{
			name: "Gogs 页面", want: "Gogs",
			asset:   model.Asset{Host: "h", Port: 3000, Title: "Gogs: Go Git Service"},
			headers: hdr("Set-Cookie", "gogs_incredible=abc123; Path=/"),
			body:    `<html><head><title>Gogs: Go Git Service</title><meta name="author" content="Gogs" /></head><body>Powered by Gogs</body></html>`,
		},
		{
			name: "Drone CI 页面", want: "Drone CI",
			asset: model.Asset{Host: "h", Port: 80, Title: "Drone CI"},
			body:  `<html><head><title>Drone CI</title></head><body><div id="drone"></div><script src="/static/drone.js"></script></body></html>`,
		},
		{
			name: "Argo CD 页面", want: "Argo CD",
			asset: model.Asset{Host: "h", Port: 443, Title: "Argo CD"},
			body:  `<html><head><title>Argo CD</title><base href="/argo-cd/"></head><body><script src="/argo-cd/static/main.js"></script><div>Argo CD</div></body></html>`,
		},
		{
			name: "Bitbucket 页面", want: "Bitbucket",
			asset:   model.Asset{Host: "h", Port: 7990, Title: "Bitbucket"},
			headers: hdr("X-Bitbucket", "8.19.4", "Server", "Bitbucket"),
			body:    `<html><head><title>Bitbucket</title></head><body><div class="commit-file-list">Bitbucket</div></body></html>`,
		},
		{
			name: "TeamCity 页面", want: "JetBrains TeamCity",
			asset: model.Asset{Host: "h", Port: 8111, Title: "TeamCity"},
			body:  `<html><head><title>TeamCity</title></head><body><a href="/app/rest/server">TeamCity 2023.11.3</a></body></html>`,
		},
		{
			name: "Bamboo 页面", want: "Atlassian Bamboo",
			asset: model.Asset{Host: "h", Port: 8085, Title: "Bamboo"},
			body:  `<html><head><title>Bamboo</title></head><body><a href="/bamboo/browse/PROJ">Atlassian Bamboo</a></body></html>`,
		},
		{
			name: "Rundeck 页面", want: "Rundeck",
			asset: model.Asset{Host: "h", Port: 4440, Title: "Rundeck"},
			body:  `<html><head><title>Rundeck</title><link href="/rundeck/static/css/rundeck.css"></head><body>Rundeck</body></html>`,
		},
		{
			name: "Ansible AWX 页面", want: "Ansible AWX",
			asset:   model.Asset{Host: "h", Port: 80, Title: "AWX"},
			headers: hdr("X-AWX", "24.2.0"),
			body:    `<html><head><title>AWX</title></head><body><script src="/static/awx/main.js"></script><div>AWX</div></body></html>`,
		},
		{
			name: "Spinnaker 页面", want: "Spinnaker",
			asset: model.Asset{Host: "h", Port: 9000, Title: "Spinnaker"},
			body:  `<html><head><title>Spinnaker</title></head><body><div id="spinnaker"></div></body></html>`,
		},

		// ---------------- 大数据 / 搜索 / 消息 ----------------
		{
			name: "Hadoop NameNode UI", want: "Hadoop NameNode",
			asset: model.Asset{Host: "h", Port: 9870, Title: "NameNode"},
			body:  `<html><head><title>NameNode</title></head><body><h1>NameNode</h1><a href="/dfshealth.html">Hadoop Overview</a></body></html>`,
		},
		{
			name: "YARN ResourceManager UI", want: "Hadoop YARN ResourceManager",
			asset: model.Asset{Host: "h", Port: 8088, Title: "ResourceManager"},
			body:  `<html><head><title>ResourceManager</title></head><body><h1>ResourceManager</h1><span>Hadoop</span><a href="/cluster/apps">yarn</a></body></html>`,
		},
		{
			name: "Spark Master UI", want: "Spark Master UI",
			asset: model.Asset{Host: "h", Port: 8080, Title: "Spark Master at spark://master:7077"},
			body:  `<html><head><title>Spark Master at spark://master:7077</title></head><body><h3>Spark Master: spark://master:7077</h3><a href="/">Back to Master</a></body></html>`,
		},
		{
			name: "Spark Worker UI", want: "Spark Worker UI",
			asset: model.Asset{Host: "h", Port: 8081, Title: "Spark Worker at worker:8081"},
			body:  `<html><head><title>Spark Worker at worker:8081</title></head><body><h3>Spark Worker</h3><a href="/logPage/?workerId=worker-1">Logs</a></body></html>`,
		},
		{
			name: "Flink Dashboard", want: "Apache Flink Dashboard",
			asset: model.Asset{Host: "h", Port: 8081, Title: "Apache Flink Dashboard"},
			body:  `<html><head><title>Apache Flink Dashboard</title></head><body><div id="flink-dashboard">Flink Dashboard</div></body></html>`,
		},
		{
			name: "ActiveMQ 控制台", want: "Apache ActiveMQ",
			asset: model.Asset{Host: "h", Port: 8161, Title: "ActiveMQ"},
			body:  `<html><head><title>ActiveMQ</title></head><body><div id="activemq">Apache ActiveMQ</div></body></html>`,
		},
		{
			name: "RocketMQ Console", want: "RocketMQ Console",
			asset: model.Asset{Host: "h", Port: 8080, Title: "RocketMQ Console"},
			body:  `<html><head><title>RocketMQ Console</title></head><body><script src="/rocketmq-console/static/js/app.js"></script></body></html>`,
		},
		{
			name: "Apache Pulsar 管理接口", want: "Apache Pulsar",
			asset: model.Asset{Host: "h", Port: 8080},
			body:  `{"brokerServiceUrl":"pulsar://broker-1:6650","brokerServiceUrlTls":"pulsar+ssl://broker-1:6651","serviceUrl":"http://broker-1:8080"}`,
		},
		{
			name: "Apache Airflow 页面", want: "Apache Airflow",
			asset:   model.Asset{Host: "h", Port: 8080, Title: "Airflow"},
			headers: hdr("Set-Cookie", "session=eyJ1c2VyX2lkIjoiMSJ9.aBcDeF.0123456789abcdef; Path=/; HttpOnly"),
			body:    `<html><head><title>Airflow</title></head><body><div id="dags">Airflow 2.9.1</div></body></html>`,
		},
		{
			name: "Apache Superset 页面", want: "Apache Superset",
			asset: model.Asset{Host: "h", Port: 8088, Title: "Superset"},
			body:  `<html><head><title>Superset</title></head><body><div id="app">Superset</div></body></html>`,
		},
		{
			name: "Metabase 页面", want: "Metabase",
			asset:   model.Asset{Host: "h", Port: 3000, Title: "Metabase"},
			headers: hdr("X-Metabase-Version", "0.49.9"),
			body:    `<html><head><title>Metabase</title></head><body><div id="root">Metabase</div></body></html>`,
		},
		{
			name: "Apache Kylin 页面", want: "Apache Kylin",
			asset: model.Asset{Host: "h", Port: 7070, Title: "Kylin"},
			body:  `<html><head><title>Kylin</title></head><body><div id="kylin">Apache Kylin</div></body></html>`,
		},
		{
			name: "Apache Doris FE UI", want: "Apache Doris",
			asset: model.Asset{Host: "h", Port: 8030, Title: "Doris FE"},
			body:  `<html><head><title>Doris FE</title></head><body><div id="doris">Doris FE 2.1.3</div></body></html>`,
		},
		{
			name: "StarRocks FE UI", want: "StarRocks",
			asset: model.Asset{Host: "h", Port: 8030, Title: "StarRocks FE"},
			body:  `<html><head><title>StarRocks FE</title></head><body><div id="starrocks">StarRocks 3.2.2</div></body></html>`,
		},

		// ---------------- 监控 / 日志 ----------------
		{
			name: "Nagios Core 页面", want: "Nagios",
			asset: model.Asset{Host: "h", Port: 80, Title: "Nagios Core"},
			body:  `<html><head><title>Nagios Core</title></head><body><div id="nagios">Nagios Core 4.4.13</div></body></html>`,
		},
		{
			name: "Icinga Web 页面", want: "Icinga",
			asset: model.Asset{Host: "h", Port: 80, Title: "Icinga Web 2"},
			body:  `<html><head><title>Icinga Web 2</title></head><body><div id="icinga">Icinga Web 2.12.1</div></body></html>`,
		},
		{
			name: "Prometheus Alertmanager", want: "Prometheus Alertmanager",
			asset: model.Asset{Host: "h", Port: 9093, Title: "Alertmanager"},
			body:  `<html><head><title>Alertmanager</title></head><body><script src="/static/script.js"></script><div>Alertmanager</div></body></html>`,
		},
		{
			name: "VictoriaMetrics vmui", want: "VictoriaMetrics",
			asset:   model.Asset{Host: "h", Port: 8428, Title: "VictoriaMetrics"},
			headers: hdr("X-Server-Hostname", "vm-1"),
			body:    `<html><head><title>VictoriaMetrics</title></head><body><div id="vmui">VMUI</div></body></html>`,
		},
		{
			name: "Netdata 页面", want: "Netdata",
			asset:   model.Asset{Host: "h", Port: 19999, Title: "Netdata"},
			headers: hdr("X-Netdata", "1.45.0"),
			body:    `<html><head><title>Netdata</title></head><body><div id="netdata">Netdata</div></body></html>`,
		},
		{
			name: "Cacti 页面", want: "Cacti Monitoring", extra: []string{"Cacti"},
			asset: model.Asset{Host: "h", Port: 80, Title: "Cacti"},
			body:  `<html><head><title>Cacti</title></head><body><div id="cacti">Cacti 1.2.26</div></body></html>`,
		},
		{
			name: "Open-Falcon 页面", want: "Open-Falcon",
			asset: model.Asset{Host: "h", Port: 8080, Title: "Open-Falcon"},
			body:  `<html><head><title>Open-Falcon</title></head><body><div>Open-Falcon Dashboard</div></body></html>`,
		},
		{
			name: "Graylog 页面", want: "Graylog",
			asset:   model.Asset{Host: "h", Port: 9000, Title: "Graylog"},
			headers: hdr("X-Graylog-Node-Id", "8f3c1d2e-1234-5678-9abc-def012345678"),
			body:    `<html><head><title>Graylog</title></head><body><script src="/assets/graylog-web.js"></script><div>Graylog</div></body></html>`,
		},
		{
			name: "Jaeger UI", want: "Jaeger",
			asset: model.Asset{Host: "h", Port: 16686, Title: "Jaeger UI"},
			body:  `<html><head><title>Jaeger UI</title></head><body><script src="/static/jaeger-ui.js"></script><div>Jaeger</div></body></html>`,
		},
		{
			name: "SkyWalking UI", want: "Apache SkyWalking",
			asset: model.Asset{Host: "h", Port: 8080, Title: "SkyWalking"},
			body:  `<html><head><title>SkyWalking</title></head><body><div id="app">Apache SkyWalking</div></body></html>`,
		},
		{
			name: "Sentinel Dashboard", want: "Sentinel Dashboard",
			asset: model.Asset{Host: "h", Port: 8080, Title: "Sentinel Dashboard"},
			body:  `<html><head><title>Sentinel Dashboard</title></head><body><div id="app">Sentinel Dashboard</div></body></html>`,
		},
		{
			name: "Uptime Kuma", want: "Uptime Kuma",
			asset: model.Asset{Host: "h", Port: 3001, Title: "Uptime Kuma"},
			body:  `<html><head><title>Uptime Kuma</title></head><body><script src="/uptime-kuma/main.js"></script><div>Uptime Kuma</div></body></html>`,
		},

		// ---------------- 代理 / 网关 / 缓存 ----------------
		{
			name: "HAProxy 503 页", want: "HAProxy",
			asset:   model.Asset{Host: "h", Port: 80, Title: "503 Service Unavailable"},
			headers: hdr("Server", "HAProxy"),
			body:    `<html><head><title>503 Service Unavailable</title></head><body><h1>503 Service Unavailable</h1><p>No server is available to handle this request. HAProxy</p></body></html>`,
		},
		{
			name: "Varnish Guru Meditation", want: "Varnish",
			asset:   model.Asset{Host: "h", Port: 80, Title: "503 Backend fetch failed"},
			headers: hdr("X-Varnish", "327681 327680", "Via", "1.1 varnish (Varnish/7.4)"),
			body:    `<html><head><title>503 Backend fetch failed</title></head><body><h1>Guru Meditation</h1><h3>Guru Meditation:</h3><p>XID: 327681</p><hr><p>Varnish cache server</p></body></html>`,
		},
		{
			name: "Squid 错误页", want: "Squid",
			asset:   model.Asset{Host: "h", Port: 3128, Title: "ERROR: The requested URL could not be retrieved"},
			headers: hdr("Server", "squid/5.9", "Via", "1.1 squid (squid/5.9)"),
			body:    `<html><head><title>ERROR: The requested URL could not be retrieved</title></head><body><p>Generated by squid/5.9</p></body></html>`,
		},
		{
			name: "Traefik 404 页", want: "Traefik",
			asset:   model.Asset{Host: "h", Port: 80, Title: "404 page not found"},
			headers: hdr("Server", "Traefik"),
			body:    `404 page not found`,
		},
		{
			name: "Envoy 404 页", want: "Envoy",
			asset:   model.Asset{Host: "h", Port: 80, Title: "404 Not Found"},
			headers: hdr("Server", "envoy"),
			body:    `<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><hr>envoy</body></html>`,
		},
		{
			name: "Kong 网关响应", want: "Kong Gateway",
			asset:   model.Asset{Host: "h", Port: 8000},
			headers: hdr("Server", "kong/3.6.0"),
			body:    `{"message":"no Route matched with those values","request_id":"abc123"}`,
		},
		{
			name: "Apache APISIX 默认页", want: "Apache APISIX",
			asset:   model.Asset{Host: "h", Port: 9080},
			headers: hdr("Server", "APISIX/3.8.0"),
			body:    `<html><head><title>Welcome to APISIX</title></head><body><p>APISIX is running, configuration file: conf/nginx.conf</p></body></html>`,
		},
		{
			name: "RedisInsight 页面", want: "RedisInsight",
			asset: model.Asset{Host: "h", Port: 8001, Title: "RedisInsight"},
			body:  `<html><head><title>RedisInsight</title></head><body><div id="redisinsight">RedisInsight</div></body></html>`,
		},
		{
			name: "Redis Commander 页面", want: "Redis Commander",
			asset: model.Asset{Host: "h", Port: 8081, Title: "Redis Commander"},
			body:  `<html><head><title>Redis Commander</title></head><body><script src="/redis-commander/bundle.js"></script><div>Redis Commander</div></body></html>`,
		},

		// ---------------- 文件 / 协作 / Web 邮件 ----------------
		{
			name: "Nextcloud 登录页", want: "Nextcloud",
			asset:   model.Asset{Host: "h", Port: 80, Title: "Nextcloud"},
			headers: hdr("X-Nextcloud", "29.0.1"),
			body:    `<html><head><title>Nextcloud</title></head><body><input type="hidden" id="requesttoken" value="abc"><img src="/core/img/actions/logo.svg"><div>Nextcloud</div></body></html>`,
		},
		{
			name: "ownCloud 登录页", want: "ownCloud",
			asset:   model.Asset{Host: "h", Port: 80, Title: "ownCloud"},
			headers: hdr("X-Owncloud", "10.13.2"),
			body:    `<html><head><title>ownCloud</title></head><body><form data-requesttoken="xyz"><div>ownCloud</div></form></body></html>`,
		},
		{
			name: "Seafile 页面", want: "Seafile",
			asset: model.Asset{Host: "h", Port: 80, Title: "Seafile"},
			body:  `<html><head><title>Seafile</title><link rel="stylesheet" href="/media/css/seafile-ui.css"></head><body><div id="seafile">Seafile</div></body></html>`,
		},
		{
			name: "Syncthing 控制台", want: "Syncthing",
			asset:   model.Asset{Host: "h", Port: 8384, Title: "Syncthing"},
			headers: hdr("X-Syncthing-Id", "AAAAAAA-BBBBBBB-CCCCCCC-DDDDDDD-EEEEEEE-FFFFFFF-GGGGGGG-HHHHHHH"),
			body:    `<html><head><title>Syncthing</title></head><body><script src="/syncthing/core/syncthingController.js"></script></body></html>`,
		},
		{
			name: "Jupyter Notebook", want: "Jupyter Notebook",
			asset:   model.Asset{Host: "h", Port: 8888, Title: "Jupyter Notebook"},
			headers: hdr("Set-Cookie", "username-admin=2|1:0|10:1700000000|8:username|4:YWRtaW4=|abc"),
			body:    `<html><head><title>Jupyter Notebook</title></head><body><script src="/static/components/jquery/jquery.min.js"></script></body></html>`,
		},
		{
			name: "JupyterLab", want: "JupyterLab",
			asset:   model.Asset{Host: "h", Port: 8888, Title: "JupyterLab"},
			headers: hdr("Set-Cookie", "_xsrf=2|abc123|def456; Path=/"),
			body:    `<html><head><title>JupyterLab</title></head><body><script src="/lab/static/main.js"></script></body></html>`,
		}, {
			name: "RStudio Server", want: "RStudio Server",
			asset:   model.Asset{Host: "h", Port: 8787, Title: "RStudio Server"},
			headers: hdr("Set-Cookie", "rstudio=abc123|def456; Path=/; HttpOnly"),
			body:    `<html><head><title>RStudio Server</title></head><body>RStudio Server</body></html>`,
		},
		{
			name: "Kodbox 可道云", want: "Kodbox",
			asset:   model.Asset{Host: "h", Port: 80, Title: "Kodbox"},
			headers: hdr("X-Kodbox", "1.5.1"),
			body:    `<html><head><title>Kodbox</title></head><body><link rel="stylesheet" href="/static/app/app.css"><div id="kodbox">Kodbox 可道云</div></body></html>`,
		},
		{
			name: "ONLYOFFICE Document Server", want: "ONLYOFFICE Document Server",
			asset:   model.Asset{Host: "h", Port: 80, Title: "ONLYOFFICE"},
			headers: hdr("X-Documentserver", "ONLYOFFICE/7.5.1"),
			body:    `<html><head><title>ONLYOFFICE</title></head><body><script src="/web-apps/apps/api/documents/api.js"></script></body></html>`,
		},
		{
			name: "Roundcube Webmail", want: "Roundcube Webmail",
			asset:   model.Asset{Host: "h", Port: 80, Title: "Roundcube Webmail :: Welcome"},
			headers: hdr("Set-Cookie", "roundcube_sessid=abc123def456; path=/; HttpOnly"),
			body:    `<html><head><title>Roundcube Webmail :: Welcome</title></head><body><div id="loginform">Roundcube</div></body></html>`,
		},
		{
			name: "RainLoop Webmail", want: "RainLoop Webmail",
			asset:   model.Asset{Host: "h", Port: 80, Title: "RainLoop Webmail"},
			headers: hdr("X-Rainloop", "1.17.0"),
			body:    `<html><head><title>RainLoop Webmail</title></head><body><input name="rainloop_email" type="text"></body></html>`,
		},
		{
			name: "Zimbra Web Client", want: "Zimbra Web Client",
			asset: model.Asset{Host: "h", Port: 80, Title: "Zimbra Web Client"},
			body:  `<html><head><title>Zimbra Web Client</title><link href="/zimbra/css/common.css"></head><body>Zimbra</body></html>`,
		},
	}
}

// TestLibraryAppRulesMatchSamples 对每条新增规则做正样本回归：
// 断言 products 里出现期望产品名，且判据里出现该规则名。
//
// 这里刻意**不**断言 Asset.Product（= 第一条命中的产品名）：主产品名取决于规则顺序，
// 而"Tomcat 9 的响应同时命中内置的 Apache Tomcat"属于正常叠加，不是缺陷。
// 规则名写错产品名会被本断言 + TestLibraryAppRulesNoCollision 一起测出来。
func TestLibraryAppRulesMatchSamples(t *testing.T) {
	e := Default()
	cases := appRuleCases()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			a := tc.asset
			a.Host = "h"
			e.Apply(&a, tc.headers, []byte(tc.body))

			if !contains(a.Products, tc.want) {
				t.Fatalf("未命中期望产品 %q，实际 products=%v evidence=%v", tc.want, a.Products, a.Evidence)
			}
			if !contains(a.Evidence, "rule:"+tc.want) {
				t.Fatalf("命中产品 %q 但判据里没有 rule:%s（规则名写错了？）: %v",
					tc.want, tc.want, a.Evidence)
			}
		})
	}
}

// TestLibraryAppRulesNoCollision 用"别的产品"的样本做交叉验证：
// 每个正样本只允许命中自己的规则（以及 extra 里显式声明的同族父类规则），
// 命中任何其它产品都算误报。
func TestLibraryAppRulesNoCollision(t *testing.T) {
	e := Default()
	cases := appRuleCases()
	if len(cases) < 15 {
		t.Fatalf("负样本/交叉验证组数不足：只有 %d 组", len(cases))
	}
	for _, tc := range cases {
		tc := tc
		t.Run("no-collision/"+tc.name, func(t *testing.T) {
			a := tc.asset
			a.Host = "h"
			e.Apply(&a, tc.headers, []byte(tc.body))

			for _, p := range a.Products {
				if p == tc.want || contains(tc.extra, p) {
					continue
				}
				t.Errorf("误报：%q 的样本同时命中了 %q（products=%v evidence=%v）",
					tc.want, p, a.Products, a.Evidence)
			}
		})
	}
}

// 规则本身的质量门槛：名字唯一、数量达标、且不出现 favicon_hash。
func TestLibraryAppRulesShape(t *testing.T) {
	rules := libraryRulesApp()
	if len(rules) < 65 {
		t.Fatalf("应用层新增规则应 ≥65 条，实际 %d 条", len(rules))
	}

	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		key := strings.ToLower(strings.TrimSpace(r.Name))
		if key == "" {
			t.Fatal("存在缺少 name 的规则")
		}
		if seen[key] {
			t.Errorf("规则名重复（MergeRules 会静默覆盖）：%s", r.Name)
		}
		seen[key] = true
		if len(r.FaviconHash) > 0 {
			t.Errorf("规则 %s 使用 favicon_hash：无法离线校验 mmh3，禁止写入", r.Name)
		}
		if len(r.Banner) == 0 && len(r.Title) == 0 && len(r.Header) == 0 && len(r.Body) == 0 {
			t.Errorf("规则 %s 没有任何特征串", r.Name)
		}
	}

	// 与内置规则不得同名（大小写不敏感）。
	// 注意 DefaultRules() = 内置 48 条 + libraryRules()，而 libraryRules() 里就含本文件的规则，
	// 所以必须排除"我自己"这一批，否则会把自己和自己比出满屏假重复。
	builtin := make(map[string]bool, 48)
	for _, r := range DefaultRules() {
		key := strings.ToLower(strings.TrimSpace(r.Name))
		if !seen[key] {
			builtin[key] = true
		}
	}
	for key := range seen {
		if builtin[key] {
			t.Errorf("应用层规则 %q 与内置规则同名", key)
		}
	}

	// 与"基础设施与设备层"规则（同一批次并行维护）也不得同名。
	for _, r := range libraryRulesNet() {
		if seen[strings.ToLower(strings.TrimSpace(r.Name))] {
			t.Errorf("应用层规则 %q 与设备层规则同名", r.Name)
		}
	}
}

// 端口约束必须真的生效：声明的端口外不得命中。
func TestLibraryAppRulePortConstraint(t *testing.T) {
	e := Default()
	if _, products := e.MatchHTTP(&model.Asset{Port: 80}, nil, []byte(`{"couchdb":"Welcome","version":"3.3.2"}`)); contains(products, "CouchDB") {
		t.Errorf("CouchDB 规则声明了 5984，不应在 80 端口命中: %v", products)
	}
	if _, products := e.MatchHTTP(&model.Asset{Port: 5984}, nil, []byte(`{"couchdb":"Welcome","version":"3.3.2"}`)); !contains(products, "CouchDB") {
		t.Errorf("CouchDB 规则应在 5984 命中: %v", products)
	}
	if _, products := e.MatchHTTP(&model.Asset{Port: 80}, nil, []byte(`{"brokerServiceUrl":"pulsar://broker-1:6650"}`)); contains(products, "Apache Pulsar") {
		t.Errorf("Pulsar 规则声明了 8080，不应在 80 端口命中: %v", products)
	}
	if _, products := e.MatchTCP(22122, "Cassandra native protocol v5 server"); contains(products, "Cassandra") {
		t.Errorf("Cassandra 规则声明了 9042/9160，不应在 22122 命中: %v", products)
	}
}
