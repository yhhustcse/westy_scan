package fingerprint

import (
	"net/http"
	"strings"
	"testing"

	"westy_scan/internal/model"
)

// netRuleSamples 是"每条新增规则至少一个正样本"的样本表。
//
// 样本刻意写成设备真实响应风格（SSH/telnet banner 整行、Server 头、页面标题、
// 响应体片段），而不是"照抄正则"，这样规则写错时测试会真的失败。
// 每个样本只针对一条规则，其余字段留空，避免跨规则交叉命中掩盖问题。
type netRuleSample struct {
	want   string // 期望命中的规则名（= Match.Product）
	banner string
	title  string
	header map[string]string
	body   string
}

func netRuleTestSamples() []netRuleSample {
	return []netRuleSample{
		// ---------------- 网络设备（banner 侧） ----------------
		{
			want:   "Cisco IOS",
			banner: "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)",
		},
		{
			want:   "Cisco ASA",
			banner: "Cisco Adaptive Security Appliance Version 9.12(4)",
		},
		{
			want:   "Cisco IOS-XE",
			banner: "Cisco IOS Software [Everest], ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 16.6.5",
		},
		{
			want:   "Huawei VRP",
			banner: "Huawei Versatile Routing Platform Software VRP (R) software, Version 5.170 (S5720 V200R019C10SPC500)",
		},
		{
			want:   "H3C Comware",
			banner: "Comware Software, Version 7.1.070, Release 3208P03",
		},
		{
			want:   "Ruijie RGOS",
			banner: "Ruijie Networks RGOS 11.0(1)B1P5, Release(07121817)",
		},
		{
			want:   "Juniper Junos",
			banner: "JUNOS Software Release [12.1X47-D20.7]",
		},
		{
			want:  "MikroTik RouterOS",
			title: "RouterOS v6.49.7",
			body:  `<title>RouterOS v6.49.7</title><script src="js/winbox.js"></script>`,
		},

		// ---------------- 网络设备（Web 管理面） ----------------
		{
			want:   "pfSense",
			title:  "pfSense - Login",
			body:   `<link rel="stylesheet" href="/themes/pfsense/application.css">`,
			header: map[string]string{"Set-Cookie": "PHPSESSID=abc123; path=/; HttpOnly"},
		},
		{
			want:  "OPNsense",
			title: "OPNsense",
			body:  `<link rel="stylesheet" href="/ui/themes/opnsense/build/css/main.css">`,
		},
		{
			want:   "Ubiquiti UniFi",
			title:  "UniFi Network",
			header: map[string]string{"Set-Cookie": "unifises=abc; path=/"},
		},
		{
			want:   "TP-Link Router",
			title:  "TL-WR841N",
			header: map[string]string{"Server": "TP-LINK Router"},
		},
		{
			want:  "D-Link Router",
			title: "D-Link Router",
			body:  `<title>D-Link Router</title>`,
		},
		{
			want:   "NETGEAR Router",
			title:  "NETGEAR genie",
			header: map[string]string{"Set-Cookie": "XSRF_TOKEN=12345; path=/"},
		},
		{
			want:  "Aruba OS",
			title: "ArubaOS",
			body:  `<title>ArubaOS</title><p>Aruba Networks</p>`,
		},
		{
			want:  "F5 BIG-IP",
			title: "BIG-IP logout page",
			header: map[string]string{
				"Set-Cookie": "BIGipServerpool_web=1677787402.36895.0000; path=/",
				"X-WA-Info":  "[Central]",
			},
		},
		{
			want:   "Citrix NetScaler",
			title:  "Citrix Gateway",
			header: map[string]string{"Set-Cookie": "NSC_AAAC=xyz; path=/"},
		},
		{
			want:   "Huawei eSight",
			title:  "eSight",
			header: map[string]string{"Server": "Huawei-eSight"},
		},
		{
			want:  "H3C iMC",
			title: "H3C iMC",
			body:  `<a href="/imc/login.jsf">iMC 登录</a>`,
		},

		// ---------------- 安全设备 / VPN ----------------
		{
			want:   "Fortinet FortiGate",
			title:  "FortiGate",
			header: map[string]string{"Set-Cookie": "FORTIWAFSID=xyz; path=/"},
		},
		{
			want: "Palo Alto GlobalProtect",
			body: `<form action="/global-protect/login.esp" method="post">GlobalProtect Portal</form>`,
		},
		{
			want:   "SonicWall",
			title:  "SonicWall - Login",
			header: map[string]string{"Server": "SonicWALL"},
		},
		{
			want:  "Check Point Gaia",
			title: "Check Point Gaia Portal",
			body:  `<title>Check Point Gaia Portal</title>`,
		},
		{
			want:   "Sangfor SSL VPN",
			title:  "Sangfor SSL VPN",
			body:   `<a href="/por/login_psw.csp">SSL VPN</a>`,
			header: map[string]string{"Set-Cookie": "TWFID=abc; path=/"},
		},
		{
			want:   "Topsec VPN",
			title:  "天融信 TopVPN",
			header: map[string]string{"Server": "Topsec"},
		},
		{
			want:  "NSFOCUS",
			title: "NSFOCUS 绿盟科技",
			body:  `<title>NSFOCUS 绿盟科技</title>`,
		},
		{
			want:  "360 Wangshen",
			title: "360网神安全网关",
			body:  `<title>360网神安全网关</title>`,
		},
		{
			want:   "Array Networks",
			title:  "Array Networks SSL VPN",
			header: map[string]string{"Set-Cookie": "AN_SERVER=abc; path=/"},
		},
		{
			want:  "Hillstone",
			title: "Hillstone SG-6000",
			body:  `<title>Hillstone SG-6000</title>`,
		},
		{
			want:  "OpenVPN Web",
			title: "OpenVPN Connect",
			body:  `<link href="/openvpn/css/main.css"><p>OpenVPN Access Server</p>`,
		},
		{
			want:  "SoftEther VPN",
			title: "SoftEther VPN Server",
			body:  `<title>SoftEther VPN Server</title>`,
		},

		// ---------------- 安防 / 物联网 ----------------
		{
			want: "Hikvision",
			body: `<title>Hikvision Digital Video Recorder</title><form action="/doc/page/login.asp">`,
		},
		{
			want: "Dahua",
			body: `<title>Dahua Technology</title><script src="/current_config/Login.js"></script>`,
		},
		{
			want:  "Uniview",
			title: "Uniview",
			body:  `<title>Uniview 宇视科技</title>`,
		},
		{
			want:   "Axis Camera",
			title:  "AXIS 214 PTZ Network Camera",
			header: map[string]string{"Server": "AXIS 214 PTZ Network Camera"},
		},
		{
			want:   "TP-Link Camera",
			title:  "tpCamera",
			header: map[string]string{"Server": "TP-LINK Router"},
		},
		{
			want:  "Foscam",
			title: "IPCam Client",
			body:  `<title>IPCam Client</title><script src="/cgi-bin/CGIProxy.fcgi"></script>`,
		},
		{
			want:  "Embedded DVR",
			title: "DVR",
			body:  `<title>DVR</title><iframe src="/web/cgi-bin/hi3510/"></iframe>`,
		},

		// ---------------- 打印机 / 打印服务器 ----------------
		{
			want:   "HP JetDirect",
			title:  "HP LaserJet",
			header: map[string]string{"Server": "HP-ChaiSOE/1.0"},
		},
		{
			want:   "Canon Printer",
			title:  "Canon iR-ADV",
			header: map[string]string{"Server": "Canon HTTP Server"},
		},
		{
			want:  "Epson Printer",
			title: "EPSON Web Config",
			body:  `<title>EPSON Web Config</title><p>EpsonNet Config</p>`,
		},
		{
			want:  "Xerox Printer",
			title: "Xerox CentreWare",
			body:  `<title>Xerox CentreWare Internet Services</title>`,
		},
		{
			want:   "Brother Printer",
			title:  "Brother",
			header: map[string]string{"Set-Cookie": "BPLeAP=1; path=/"},
		},
		{
			want:   "IBM Print Server",
			title:  "Infoprint 1332",
			header: map[string]string{"Server": "IBM_HTTP_Server/2.0"},
		},

		// ---------------- 国产 OA / 协同 ----------------
		{
			want:   "Weaver e-cology",
			title:  "泛微 e-cology",
			body:   `<script src="/wui/theme/ecology8/jquery.js"></script>`,
			header: map[string]string{"Set-Cookie": "ecology_JSessionid=abc; path=/"},
		},
		{
			want:  "Weaver e-office",
			title: "泛微 e-office",
			body:  `<a href="/eoffice10/client/portal">e-office 门户</a>`,
		},
		{
			want:  "Seeyon A8",
			title: "致远OA",
			body:  `<a href="/seeyon/main.do">Seeyon A8</a>`,
		},
		{
			want:  "Landray EKP",
			title: "蓝凌 EKP",
			body:  `<a href="/ekp/index.jsp">Landray EKP</a>`,
		},
		{
			want:  "Tongda OA",
			title: "通达OA",
			body:  `<a href="/ispirit/login.php">Office Anywhere 2017</a>`,
		},
		{
			want:  "Huatian OA",
			title: "华天动力 OA",
			body:  `<a href="/dynamo/login.jsp">华天动力协同办公系统</a>`,
		},

		// ---------------- 国产 ERP / 财务 ----------------
		{
			want:  "Yonyou NC",
			title: "用友NC",
			body:  `<a href="/nc/servlet/VerifyCodeServlet">yonyou NC</a>`,
		},
		{
			want:  "Yonyou YonSuite",
			title: "YonSuite",
			body:  `<a href="/yonsuite/login">YonSuite 登录</a>`,
		},
		{
			want:   "Yonyou U8",
			title:  "用友U8",
			body:   `<a href="/U8Portal/login.jsp">用友U8</a>`,
			header: map[string]string{"Server": "U8"},
		},
		{
			want:  "Kingdee EAS",
			title: "金蝶EAS",
			body:  `<a href="/eas/login.jsp">Kingdee EAS</a>`,
		},
		{
			want:  "Kingdee K3 Cloud",
			title: "金蝶K3 Cloud",
			body:  `<a href="/K3Cloud/Login.aspx">K3Cloud</a>`,
		},
		{
			want:   "Inspur GS",
			title:  "浪潮GS",
			header: map[string]string{"Server": "Inspur"},
		},
		{
			want:  "Digiwin ERP",
			title: "鼎捷ERP",
			body:  `<a href="/DigiWin/Login.aspx">DigiWin ERP</a>`,
		},
		{
			want:  "SAP NetWeaver",
			title: "SAP NetWeaver Portal",
			body:  `<a href="/irj/portal">SAP NetWeaver</a>`,
		},
		{
			want:  "Oracle EBS",
			title: "Oracle E-Business Suite",
			body:  `<a href="/OA_HTML/AppsLogin">Oracle E-Business Suite</a>`,
		},

		// ---------------- 国产中间件 / 数据库 ----------------
		{
			want:   "TongWeb",
			header: map[string]string{"Server": "TongWeb/7.0"},
			body:   `<p>TongWeb Application Server</p>`,
		},
		{
			want:   "Apusic",
			header: map[string]string{"Server": "Apusic/9.0"},
			body:   `<p>Apusic Application Server</p>`,
		},
		{
			want:   "BES Application Server",
			header: map[string]string{"Server": "BES/9.5.5"},
			body:   `<p>BES Application Server</p>`,
		},
		{
			want:   "InforSuite",
			header: map[string]string{"Server": "InforSuite/9.0"},
			body:   `<p>InforSuite 中创中间件</p>`,
		},
		{
			want:   "Dameng DB",
			title:  "达梦数据库管理系统",
			body:   `<title>达梦数据库 DM8</title>`,
			header: map[string]string{"Set-Cookie": "dm8_session=abc; path=/"},
		},
		{
			want:   "KingBase",
			title:  "KingbaseES",
			body:   `<title>KingbaseES 人大金仓</title>`,
			header: map[string]string{"Server": "KingBase"},
		},
		{
			want:  "Shentong DB",
			title: "神通数据库",
			body:  `<title>神通数据库管理系统 OSCAR</title>`,
		},
		{
			want:   "GBase",
			title:  "GBase 8a",
			header: map[string]string{"Server": "GBase"},
		},
		{
			want:  "OceanBase",
			title: "OceanBase",
			body:  `<title>OceanBase 云平台</title>`,
		},
		{
			want:  "TiDB",
			title: "TiDB Dashboard",
			body:  `<title>TiDB Dashboard</title><p>TiKV</p>`,
		},
		{
			want:   "PolarDB",
			title:  "PolarDB",
			header: map[string]string{"X-Powered-By": "PolarDB"},
		},

		// ---------------- 网管 / 运维平台 ----------------
		{
			want:  "Cacti",
			title: "Cacti",
			body:  `<title>Cacti</title><img src="/cacti/images/cacti_logo.gif">`,
		},
		{
			want:   "SolarWinds",
			title:  "SolarWinds Orion",
			header: map[string]string{"Set-Cookie": "SolarWinds.Session=abc; path=/"},
		},
		{
			want:  "PRTG",
			title: "PRTG Network Monitor",
			body:  `<title>PRTG Network Monitor</title><p>Paessler AG</p>`,
		},
		{
			want:  "WhatsUp Gold",
			title: "WhatsUp Gold",
			body:  `<title>WhatsUp Gold</title><p>NmConsole</p>`,
		},
		{
			want:  "ManageEngine",
			title: "ManageEngine OpManager",
			body:  `<title>ManageEngine OpManager</title><p>AdventNet</p>`,
		},
		{
			want:  "Zoho Corp",
			title: "Zoho ManageEngine",
			body:  `<p>Zoho Corporation</p>`,
		},
		{
			want:  "Ruijie RIIL",
			title: "锐捷 RIIL",
			body:  `<title>RIIL 综合运维平台</title>`,
		},
		{
			want:  "JumpServer",
			title: "JumpServer",
			body:  `<form action="/core/auth/login/" method="post">JumpServer 堡垒机</form>`,
		},
		{
			want:  "Teleport",
			title: "Teleport",
			body:  `<script src="/webapi/ping"></script><p>Teleport</p>`,
		},
		{
			want:  "Qizhi Bastion",
			title: "齐治堡垒机",
			body:  `<title>齐治堡垒机</title><p>shterm</p>`,
		},
		{
			want:  "Yunbox",
			title: "行云管家",
			body:  `<title>行云管家</title><p>cloudbility</p>`,
		},

		// ---------------- 存储 / 备份 ----------------
		{
			want:  "Synology DSM",
			title: "Synology DiskStation",
			body:  `<a href="/webman/index.cgi">DSM 7.2</a>`,
		},
		{
			want:  "QNAP QTS",
			title: "QNAP Turbo NAS",
			body:  `<title>QTS Web Administration</title>`,
		},
		{
			want:  "TrueNAS",
			title: "TrueNAS",
			body:  `<title>TrueNAS</title><p>FreeNAS</p>`,
		},
		{
			want:  "Huawei OceanStor",
			title: "OceanStor DeviceManager",
			body:  `<title>OceanStor DeviceManager</title>`,
		},
		{
			want:  "EMC Unisphere",
			title: "Unisphere",
			body:  `<title>Unisphere</title><p>EMC Corporation</p>`,
		},
		{
			want:  "NetApp ONTAP",
			title: "NetApp ONTAP System Manager",
			body:  `<title>NetApp ONTAP System Manager</title>`,
		},
		{
			want:  "Ceph Dashboard",
			title: "Ceph",
			body:  `<title>Ceph</title><script src="ceph.js"></script>`,
		},
		{
			want:  "Veeam",
			title: "Veeam Backup Enterprise Manager",
			body:  `<title>Veeam Backup</title>`,
		},

		// ---------------- 工控（只有端口可认，样本就是"端口上有响应"） ----------------
		{
			want: "Siemens S7 PLC",
		},
		{
			want: "Modbus TCP",
		},
		{
			want: "SNMP",
		},
	}
}

// sampleAsset 把样本折算成一个 Asset：端口取规则声明端口（规则不限端口时用 80）。
func sampleAsset(r Rule, s netRuleSample) *model.Asset {
	port := 80
	if len(r.Ports) > 0 {
		port = r.Ports[0]
	}
	a := &model.Asset{Host: "10.0.0.1", Port: port, Title: s.title}
	if s.banner != "" {
		a.Banner = s.banner
	}
	return a
}

func sampleHeaders(s netRuleSample) http.Header {
	if len(s.header) == 0 {
		return nil
	}
	h := http.Header{}
	for k, v := range s.header {
		h.Set(k, v)
	}
	return h
}

// TestLibraryNetRulesMatchSamples 表驱动验证每条新增规则都有能命中它的真实风格样本，
// 并且断言 Product 等值（不是只断言"有命中"）。
func TestLibraryNetRulesMatchSamples(t *testing.T) {
	rules := libraryRulesNet()
	if len(rules) == 0 {
		t.Fatal("libraryRulesNet 不应为空")
	}
	samples := netRuleTestSamples()

	byName := make(map[string]Rule, len(rules))
	for _, r := range rules {
		if _, dup := byName[r.Name]; dup {
			t.Errorf("规则名重复: %q", r.Name)
		}
		byName[r.Name] = r
	}
	sampleByName := make(map[string]netRuleSample, len(samples))
	for _, s := range samples {
		if _, dup := sampleByName[s.want]; dup {
			t.Errorf("样本表中 %q 出现多次，无法一一对应", s.want)
		}
		sampleByName[s.want] = s
	}

	// 完整性：每条规则都必须有正样本；每个样本都必须对应一条真实规则（防拼写错误）
	for name := range byName {
		if _, ok := sampleByName[name]; !ok {
			t.Errorf("规则 %q 没有正样本（死规则）", name)
		}
	}
	for name := range sampleByName {
		if _, ok := byName[name]; !ok {
			t.Errorf("样本 %q 找不到对应规则（改名后忘了改测试？）", name)
		}
	}

	e, err := New(rules)
	if err != nil {
		t.Fatalf("新增规则编译失败: %v", err)
	}

	fields := func(s netRuleSample) string {
		var b strings.Builder
		if s.banner != "" {
			b.WriteString("banner=" + s.banner + " ")
		}
		if s.title != "" {
			b.WriteString("title=" + s.title + " ")
		}
		if len(s.header) > 0 {
			b.WriteString("header=")
			for k, v := range s.header {
				b.WriteString(k + ": " + v + " ")
			}
		}
		if s.body != "" {
			b.WriteString("body=" + s.body)
		}
		return b.String()
	}

	for name, s := range sampleByName {
		s := s
		name := name
		t.Run(name, func(t *testing.T) {
			r := byName[name]
			a := sampleAsset(r, s)
			h := sampleHeaders(s)
			var body []byte
			if s.body != "" {
				body = []byte(s.body)
			}

			matched := make(map[string]bool)
			for _, m := range e.MatchTCPAll(a.Port, s.banner) {
				matched[m.Product] = true
			}
			for _, m := range e.MatchHTTPAll(a, h, body) {
				matched[m.Product] = true
			}

			if !matched[name] {
				t.Fatalf("样本未命中规则 %q（端口 %d，%s）", name, a.Port, fields(s))
			}

			if len(s.banner)+len(s.title)+len(s.body)+len(s.header) == 0 {
				// 纯端口规则只认端口；Apply 要求资产先有 banner/HTTP 响应才会跑匹配，
				// 这里不再断言 Asset，避免把"引擎调用前提"误判成规则缺陷。
				if r.Confidence != model.ConfidenceLow {
					t.Fatalf("纯端口规则 %q 必须显式标 low，实际 %q", name, r.Confidence)
				}
				return
			}

			// Product 必须等于规则名；再走一遍 Apply 确认落到资产上的主产品名。
			a2 := sampleAsset(r, s)
			e.Apply(a2, h, body)
			if a2.Product != name && !contains(a2.Products, name) {
				t.Fatalf("Apply 后资产产品不含 %q: product=%q products=%v", name, a2.Product, a2.Products)
			}

			// 证据必须是规则名，避免"命中了但判据对不上"。
			if !contains(a2.Evidence, "rule:"+name) {
				t.Fatalf("Apply 后缺少判据 rule:%s: %v", name, a2.Evidence)
			}
		})
	}
}

// TestLibraryNetRulesNoCollision 用负样本做交叉验证：
// A 厂商的真实响应不得同时命中 B 厂商规则（设备类规则最典型的误报来源）。
func TestLibraryNetRulesNoCollision(t *testing.T) {
	rules := libraryRulesNet()
	e, err := New(rules)
	if err != nil {
		t.Fatalf("新增规则编译失败: %v", err)
	}

	portOf := func(name string) int {
		for _, r := range rules {
			if r.Name == name {
				if len(r.Ports) > 0 {
					return r.Ports[0]
				}
				return 80
			}
		}
		t.Fatalf("规则 %q 不存在", name)
		return 0
	}

	type sample struct {
		name   string
		banner string
		title  string
		header map[string]string
		body   string
	}
	type collision struct {
		desc  string
		of    string // 用哪条规则的端口
		s     sample
		avoid []string
	}

	cases := []collision{
		{
			desc: "华为 VRP banner 不得命中 H3C/Ruijie/Juniper",
			of:   "Huawei VRP",
			s: sample{
				name:   "Huawei VRP",
				banner: "Huawei Versatile Routing Platform Software VRP (R) software, Version 5.170",
			},
			avoid: []string{"H3C Comware", "Ruijie RGOS", "Juniper Junos", "Cisco IOS", "MikroTik RouterOS"},
		},
		{
			desc: "H3C Comware banner 不得命中华为/锐捷/思科",
			of:   "H3C Comware",
			s: sample{
				name:   "H3C Comware",
				banner: "Comware Software, Version 7.1.070, Release 3208P03",
			},
			avoid: []string{"Huawei VRP", "Ruijie RGOS", "Cisco IOS", "Cisco IOS-XE", "Juniper Junos"},
		},
		{
			desc: "Cisco IOS banner 不得命中华为/H3C/锐捷/Juniper",
			of:   "Cisco IOS",
			s: sample{
				name:   "Cisco IOS",
				banner: "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11",
			},
			avoid: []string{"Huawei VRP", "H3C Comware", "Ruijie RGOS", "Cisco ASA", "Cisco IOS-XE", "Juniper Junos"},
		},
		{
			desc: "Cisco ASA banner 不得命中 Cisco IOS / IOS-XE",
			of:   "Cisco ASA",
			s: sample{
				name:   "Cisco ASA",
				banner: "Cisco Adaptive Security Appliance Version 9.12(4)",
			},
			avoid: []string{"Cisco IOS", "Cisco IOS-XE", "Huawei VRP"},
		},
		{
			desc: "Juniper JUNOS banner 不得命中思科/H3C/华为",
			of:   "Juniper Junos",
			s: sample{
				name:   "Juniper Junos",
				banner: "JUNOS Software Release [12.1X47-D20.7]",
			},
			avoid: []string{"MikroTik RouterOS", "Cisco IOS", "H3C Comware", "Huawei VRP", "Ruijie RGOS", "Cisco ASA"},
		},
		{
			desc: "MikroTik RouterOS 页面不得命中 pfSense/OPNsense",
			of:   "MikroTik RouterOS",
			s:    sample{name: "MikroTik RouterOS", title: "RouterOS v6.49.7", body: `<title>RouterOS v6.49.7</title>`},
			avoid: []string{"pfSense", "OPNsense", "TP-Link Router", "D-Link Router",
				"NETGEAR Router", "Aruba OS"},
		},
		{
			desc:  "pfSense 登录页不得命中 OPNsense / D-Link",
			of:    "pfSense",
			s:     sample{name: "pfSense", title: "pfSense - Login", body: `Please login to pfSense`},
			avoid: []string{"OPNsense", "D-Link Router", "NETGEAR Router", "TP-Link Router", "MikroTik RouterOS"},
		},
		{
			desc:  "OPNsense 登录页不得命中 pfSense",
			of:    "OPNsense",
			s:     sample{name: "OPNsense", title: "OPNsense", body: `<title>OPNsense</title>`},
			avoid: []string{"pfSense", "MikroTik RouterOS", "D-Link Router"},
		},
		{
			desc:  "F5 BIG-IP 不得命中 Citrix NetScaler / 普通站点",
			of:    "F5 BIG-IP",
			s:     sample{name: "F5 BIG-IP", header: map[string]string{"Set-Cookie": "BIGipServerpool_web=1677787402.36895.0000; path=/"}},
			avoid: []string{"Citrix NetScaler", "Fortinet FortiGate", "SonicWall", "Aruba OS"},
		},
		{
			desc:  "Citrix NSC_ Cookie 不得命中 F5 / Fortinet",
			of:    "Citrix NetScaler",
			s:     sample{name: "Citrix NetScaler", header: map[string]string{"Set-Cookie": "NSC_AAAC=xyz; path=/"}},
			avoid: []string{"F5 BIG-IP", "Fortinet FortiGate", "SonicWall", "Sangfor SSL VPN"},
		},
		{
			desc:  "FortiGate 页面不得命中 SonicWall / Sangfor / Palo Alto",
			of:    "Fortinet FortiGate",
			s:     sample{name: "Fortinet FortiGate", title: "FortiGate", body: `/sslvpn/portal`},
			avoid: []string{"SonicWall", "Sangfor SSL VPN", "Palo Alto GlobalProtect", "NSFOCUS", "Hillstone"},
		},
		{
			desc:  "SonicWall 登录页不得命中 FortiGate / Palo Alto",
			of:    "SonicWall",
			s:     sample{name: "SonicWall", title: "SonicWall - Login", body: `/sonicui/`},
			avoid: []string{"Fortinet FortiGate", "Palo Alto GlobalProtect", "NSFOCUS", "Hillstone", "Citrix NetScaler"},
		},
		{
			desc:  "Hikvision 响应不得命中 Dahua / Uniview / Axis / DVR",
			of:    "Hikvision",
			s:     sample{name: "Hikvision", body: `<title>Hikvision</title><form action="/doc/page/login.asp">`},
			avoid: []string{"Dahua", "Uniview", "Axis Camera", "Foscam", "Embedded DVR", "TP-Link Camera"},
		},
		{
			desc:  "Dahua 响应不得命中 Hikvision / Uniview / DVR",
			of:    "Dahua",
			s:     sample{name: "Dahua", body: `<title>Dahua Technology</title><script src="/current_config/Login.js"></script>`},
			avoid: []string{"Hikvision", "Uniview", "Axis Camera", "Embedded DVR", "Foscam"},
		},
		{
			desc:  "Axis 摄像头不得命中 Hikvision / Dahua",
			of:    "Axis Camera",
			s:     sample{name: "Axis Camera", header: map[string]string{"Server": "AXIS 214 PTZ Network Camera"}},
			avoid: []string{"Hikvision", "Dahua", "Uniview", "Foscam", "Embedded DVR"},
		},
		{
			desc:  "HP 打印机不得命中 Canon / Epson / Brother",
			of:    "HP JetDirect",
			s:     sample{name: "HP JetDirect", header: map[string]string{"Server": "HP-ChaiSOE/1.0"}},
			avoid: []string{"Canon Printer", "Epson Printer", "Xerox Printer", "Brother Printer", "IBM Print Server"},
		},
		{
			desc:  "Canon 打印服务器不得命中 Epson / HP",
			of:    "Canon Printer",
			s:     sample{name: "Canon Printer", header: map[string]string{"Server": "Canon HTTP Server"}},
			avoid: []string{"Epson Printer", "HP JetDirect", "Xerox Printer", "Brother Printer"},
		},
		{
			desc:  "泛微 e-cology 不得命中 e-office / 致远 / 蓝凌",
			of:    "Weaver e-cology",
			s:     sample{name: "Weaver e-cology", body: `<script src="/wui/theme/ecology8/jquery.js"></script>`},
			avoid: []string{"Weaver e-office", "Seeyon A8", "Landray EKP", "Tongda OA", "Huatian OA"},
		},
		{
			desc:  "致远 OA 不得命中泛微 / 蓝凌 / 通达",
			of:    "Seeyon A8",
			s:     sample{name: "Seeyon A8", body: `<a href="/seeyon/main.do">Seeyon A8</a>`},
			avoid: []string{"Weaver e-cology", "Weaver e-office", "Landray EKP", "Tongda OA", "Huatian OA"},
		},
		{
			desc:  "蓝凌 EKP 不得命中泛微 / 致远 / 通达",
			of:    "Landray EKP",
			s:     sample{name: "Landray EKP", body: `<a href="/ekp/index.jsp">Landray EKP</a>`},
			avoid: []string{"Weaver e-cology", "Weaver e-office", "Seeyon A8", "Tongda OA", "Huatian OA"},
		},
		{
			desc:  "通达 OA 不得命中泛微 / 致远 / 蓝凌",
			of:    "Tongda OA",
			s:     sample{name: "Tongda OA", body: `<a href="/ispirit/login.php">Office Anywhere</a>`},
			avoid: []string{"Weaver e-cology", "Weaver e-office", "Seeyon A8", "Landray EKP", "Huatian OA"},
		},
		{
			desc:  "用友 NC 不得命中金蝶 / YonSuite / K3",
			of:    "Yonyou NC",
			s:     sample{name: "Yonyou NC", body: `<a href="/nc/servlet/VerifyCodeServlet">yonyou NC</a>`},
			avoid: []string{"Kingdee EAS", "Kingdee K3 Cloud", "Yonyou YonSuite", "Yonyou U8", "SAP NetWeaver", "Oracle EBS"},
		},
		{
			desc:  "金蝶 EAS 不得命中用友 / K3",
			of:    "Kingdee EAS",
			s:     sample{name: "Kingdee EAS", body: `<a href="/eas/login.jsp">Kingdee EAS</a>`},
			avoid: []string{"Yonyou NC", "Yonyou YonSuite", "Yonyou U8", "Kingdee K3 Cloud", "SAP NetWeaver"},
		},
		{
			desc:  "金蝶 K3 Cloud 不得命中用友 NC / EAS",
			of:    "Kingdee K3 Cloud",
			s:     sample{name: "Kingdee K3 Cloud", body: `<a href="/K3Cloud/Login.aspx">K3Cloud</a>`},
			avoid: []string{"Yonyou NC", "Yonyou YonSuite", "Kingdee EAS", "SAP NetWeaver"},
		},
		{
			desc:  "SAP NetWeaver 不得命中 Oracle EBS / 用友",
			of:    "SAP NetWeaver",
			s:     sample{name: "SAP NetWeaver", body: `<a href="/irj/portal">SAP NetWeaver</a>`},
			avoid: []string{"Oracle EBS", "Yonyou NC", "Kingdee EAS", "Kingdee K3 Cloud"},
		},
		{
			desc:  "TongWeb 不得命中 Apusic / BES / InforSuite",
			of:    "TongWeb",
			s:     sample{name: "TongWeb", header: map[string]string{"Server": "TongWeb/7.0"}},
			avoid: []string{"Apusic", "BES Application Server", "InforSuite", "Dameng DB", "KingBase"},
		},
		{
			desc:  "达梦 DM8 不得命中人大金仓 / 神通 / GBase",
			of:    "Dameng DB",
			s:     sample{name: "Dameng DB", body: `<title>达梦数据库 DM8</title>`},
			avoid: []string{"KingBase", "Shentong DB", "GBase", "OceanBase", "TiDB", "PolarDB"},
		},
		{
			desc:  "人大金仓不得命中达梦 / GBase / OceanBase",
			of:    "KingBase",
			s:     sample{name: "KingBase", body: `<title>KingbaseES 人大金仓</title>`},
			avoid: []string{"Dameng DB", "Shentong DB", "GBase", "OceanBase", "TiDB", "PolarDB"},
		},
		{
			desc:  "OceanBase 不得命中 TiDB / GBase / 达梦",
			of:    "OceanBase",
			s:     sample{name: "OceanBase", body: `<title>OceanBase 云平台</title>`},
			avoid: []string{"TiDB", "GBase", "Dameng DB", "KingBase", "PolarDB"},
		},
		{
			desc:  "Zabbix 之外：PRTG 不得命中 SolarWinds / WhatsUp / ManageEngine",
			of:    "PRTG",
			s:     sample{name: "PRTG", body: `<title>PRTG Network Monitor</title><p>Paessler AG</p>`},
			avoid: []string{"SolarWinds", "WhatsUp Gold", "ManageEngine", "Cacti", "Zoho Corp", "Zabbix"},
		},
		{
			desc:  "SolarWinds 不得命中 ManageEngine / PRTG",
			of:    "SolarWinds",
			s:     sample{name: "SolarWinds", body: `<title>SolarWinds Orion</title>`},
			avoid: []string{"ManageEngine", "PRTG", "WhatsUp Gold", "Cacti", "Zoho Corp"},
		},
		{
			desc:  "群晖 DSM 不得命中 QNAP / TrueNAS",
			of:    "Synology DSM",
			s:     sample{name: "Synology DSM", body: `<a href="/webman/index.cgi">Synology DSM</a>`},
			avoid: []string{"QNAP QTS", "TrueNAS", "Huawei OceanStor", "EMC Unisphere", "NetApp ONTAP", "Ceph Dashboard"},
		},
		{
			desc:  "QNAP 不得命中群晖 / TrueNAS / NetApp",
			of:    "QNAP QTS",
			s:     sample{name: "QNAP QTS", body: `<title>QNAP Turbo NAS</title><p>QTS</p>`},
			avoid: []string{"Synology DSM", "TrueNAS", "NetApp ONTAP", "Huawei OceanStor", "EMC Unisphere"},
		},
		{
			desc:  "NetApp ONTAP 不得命中群晖 / EMC",
			of:    "NetApp ONTAP",
			s:     sample{name: "NetApp ONTAP", body: `<title>NetApp ONTAP System Manager</title>`},
			avoid: []string{"Synology DSM", "QNAP QTS", "EMC Unisphere", "TrueNAS", "Huawei OceanStor"},
		},
		{
			desc:  "JumpServer 不得命中 Teleport / 齐治 / 行云管家",
			of:    "JumpServer",
			s:     sample{name: "JumpServer", body: `<form action="/core/auth/login/">JumpServer</form>`},
			avoid: []string{"Teleport", "Qizhi Bastion", "Yunbox", "ManageEngine", "Zoho Corp"},
		},
		{
			desc:  "泛微 e-office 不得命中 e-cology / 致远",
			of:    "Weaver e-office",
			s:     sample{name: "Weaver e-office", body: `<a href="/eoffice10/client/portal">e-office</a>`},
			avoid: []string{"Weaver e-cology", "Seeyon A8", "Landray EKP", "Tongda OA"},
		},
		{
			desc:  "Veeam 不得命中 NetApp / EMC",
			of:    "Veeam",
			s:     sample{name: "Veeam", body: `<title>Veeam Backup Enterprise Manager</title>`},
			avoid: []string{"NetApp ONTAP", "EMC Unisphere", "Ceph Dashboard", "TrueNAS"},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.desc, func(t *testing.T) {
			port := portOf(c.of)
			a := &model.Asset{Host: "10.0.0.2", Port: port, Title: c.s.title}
			h := http.Header{}
			for k, v := range c.s.header {
				h.Set(k, v)
			}
			var body []byte
			if c.s.body != "" {
				body = []byte(c.s.body)
			}

			products := make(map[string]bool)
			for _, m := range e.MatchTCPAll(port, c.s.banner) {
				products[m.Product] = true
			}
			for _, m := range e.MatchHTTPAll(a, h, body) {
				products[m.Product] = true
			}
			if !products[c.s.name] {
				t.Fatalf("负样本自身未命中 %q，交叉验证无意义（端口 %d）", c.s.name, port)
			}
			for _, avoid := range c.avoid {
				if products[avoid] {
					t.Errorf("误报: %q 的响应同时命中了 %q", c.s.name, avoid)
				}
			}
		})
	}
}

// TestLibraryNetRulesQualityGate 把 rules_library.go 的质量门槛落成可执行检查：
// 禁止裸 `.*`、禁止空 header 值正则、必须有具体字面量、大小写不敏感必须显式 (?i)。
func TestLibraryNetRulesQualityGate(t *testing.T) {
	for _, r := range libraryRulesNet() {
		if strings.TrimSpace(r.Name) == "" {
			t.Error("规则缺少 name")
		}
		if len(r.FaviconHash) > 0 {
			t.Errorf("规则 %q 不应写 favicon_hash（无法离线验证 mmh3）", r.Name)
		}
		patterns := make([]string, 0, len(r.Banner)+len(r.Title)+len(r.Body)+len(r.Header))
		patterns = append(patterns, r.Banner...)
		patterns = append(patterns, r.Title...)
		patterns = append(patterns, r.Body...)
		for _, v := range r.Header {
			patterns = append(patterns, v)
		}
		if len(patterns) == 0 && len(r.Ports) == 0 {
			t.Errorf("规则 %q 既没有特征串也没有端口，永远不会命中", r.Name)
		}
		if len(patterns) > 0 && len(r.Ports) == 0 && r.Service == "" {
			t.Errorf("规则 %q 缺少 service", r.Name)
		}
		if len(patterns) == 0 && r.Confidence != model.ConfidenceLow {
			t.Errorf("纯端口规则 %q 必须显式标 low，实际 %q", r.Name, r.Confidence)
		}
		for k, v := range r.Header {
			if v == "" || v == ".*" || v == ".+" {
				t.Errorf("规则 %q 的 header_regex[%s]=%q 会命中任意响应头", r.Name, k, v)
			}
		}
		for _, p := range patterns {
			if p == "" {
				t.Errorf("规则 %q 存在空正则", r.Name)
			}
			if p == ".*" || strings.Contains(p, "(?=)") {
				t.Errorf("规则 %q 含裸 .*: %q", r.Name, p)
			}
			// literal 检查：去掉 (?i) 之类的内联标志后必须还有字母字面量，
			// 这样 `\d+`、`.*` 这类泛化模式无法单独成规则。
			stripped := strings.ReplaceAll(p, "(?i)", "")
			stripped = strings.ReplaceAll(stripped, "(?m)", "")
			if !strings.ContainsFunc(stripped, func(rn rune) bool {
				switch {
				case rn >= 'a' && rn <= 'z', rn >= 'A' && rn <= 'Z':
					return true
				case rn >= 0x2E80 && rn <= 0x9FFF: // CJK：中文厂商名同样是具体字面量
					return true
				default:
					return false
				}
			}) {
				t.Errorf("规则 %q 的正则 %q 没有具体字面量（泛化模式容易误报）", r.Name, p)
			}
		}
	}
}
