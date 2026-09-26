package fingerprint

// libraryRulesNet 是"基础设施与设备层"扩展规则：网络设备、安全设备/VPN、安防物联网、
// 打印与外设、国产 OA/协同、国产 ERP/财务、国产中间件与数据库、网管运维、
// 存储备份以及少量工控特征。
//
// 维护要求见 rules_library.go 顶部注释；每条规则都要在 rules_library_net_test.go
// 里有对应的正样本，否则视为"死规则"（TestLibraryNetRulesMatchSamples 会强制校验覆盖）。
//
// 设备类规则的额外约定：
//   - 只写"真实响应里确实会出现"的字面量（banner 整行、Server 头、页面标题、独特路径、
//     独特 Cookie 名），拿不准的厂商宁可不写 —— 设备 banner 记错就是长期误报/漏报；
//   - 纯端口规则只在确实没有更好特征时使用，并显式标注 low（如 Siemens S7 / Modbus 这类
//     无法离线验证 payload 的工控协议，只认端口并降级置信度）；
//   - 不写 favicon_hash（离线无法验证 mmh3，写错误报）。
func libraryRulesNet() []Rule {
	out := make([]Rule, 0, 128)
	out = append(out, netRulesTCP()...)
	out = append(out, netRulesDevices()...)
	out = append(out, netRulesSecurity()...)
	out = append(out, netRulesCamera()...)
	out = append(out, netRulesPrinter()...)
	out = append(out, netRulesOA()...)
	out = append(out, netRulesERP()...)
	out = append(out, netRulesMiddleware()...)
	out = append(out, netRulesOps()...)
	out = append(out, netRulesStorage()...)
	out = append(out, netRulesIndustrial()...)
	return out
}

// netRulesTCP 覆盖只能从 TCP Banner 识别的设备（管理面 SSH/telnet 提示符）。
func netRulesTCP() []Rule {
	return []Rule{
		{
			Name: "Cisco IOS", Service: "ssh", Ports: []int{22, 23},
			Banner: []string{`(?i)Cisco IOS Software,`, `(?i)Cisco IOS \(tm\)`},
			Title:  []string{`(?i)Cisco IOS`},
			Body:   []string{`(?i)Cisco IOS Software`},
		},
		{
			Name: "Cisco ASA", Service: "ssh", Ports: []int{22},
			Banner: []string{`(?i)Cisco Adaptive Security Appliance`, `(?i)> Copyright \(c\) \d{4} by Cisco Systems`},
			Title:  []string{`(?i)Cisco ASDM`},
			Body:   []string{`(?i)ASDM`},
		},
		{
			Name: "Cisco IOS-XE", Service: "tcp", Ports: []int{22},
			Banner: []string{`(?i)Cisco IOS Software \[Everest\]`, `(?i)Cisco IOS XE Software`},
		},
		{
			Name: "Huawei VRP", Service: "ssh", Ports: []int{22, 23},
			Banner: []string{`(?i)Huawei Versatile Routing Platform`, `(?i)VRP \(R\) software`},
			Body:   []string{`(?i)Huawei Versatile Routing Platform`},
		},
		{
			Name: "H3C Comware", Service: "ssh", Ports: []int{22, 23},
			Banner: []string{`(?i)Comware Software`, `(?i)H3C Comware Platform`},
			Header: map[string]string{"server": `(?i)comware`},
			Title:  []string{`(?i)H3C`},
			Body:   []string{`(?i)Comware Software, Version`},
		},
		{
			Name: "Ruijie RGOS", Service: "ssh", Ports: []int{22, 23},
			Banner: []string{`(?i)Ruijie Networks`, `(?i)RGOS`, `SSH-2\.0-Ruijie`},
			Body:   []string{`(?i)Ruijie`},
		},
		{
			Name: "Juniper Junos", Service: "ssh", Ports: []int{22, 23},
			Banner: []string{`(?i)JUNOS Software Release`, `(?i)JUNOS Base OS`, `(?i)Juniper Networks`},
			Title:  []string{`(?i)Juniper`},
			Body:   []string{`(?i)Juniper Web Device Manager`},
		},
		{
			Name: "MikroTik RouterOS", Service: "http",
			Banner: []string{`(?i)RouterOS`, `(?i)MikroTik`},
			Title:  []string{`(?i)RouterOS`},
			Body:   []string{`(?i)RouterOS`, `(?i)MikroTik`},
		},
	}
}

// netRulesDevices 覆盖网络设备/防火墙的 Web 管理面。
func netRulesDevices() []Rule {
	return []Rule{
		{
			Name: "pfSense", Service: "http",
			Header: map[string]string{"set-cookie": `(?i)PHPSESSID=|(?i)csrfMagicToken=`},
			Title:  []string{`(?i)pfSense`},
			Body:   []string{`(?i)pfSense`, `/themes/pfsense/`},
		},
		{
			Name: "OPNsense", Service: "http",
			Header: map[string]string{"set-cookie": `(?i)PHPSESSID=`},
			Title:  []string{`(?i)OPNsense`},
			Body:   []string{`(?i)OPNsense`, `/ui/themes/opnsense/`},
		},
		{
			Name: "Ubiquiti UniFi", Service: "http", Ports: []int{8443, 8843, 8080, 11443},
			Header: map[string]string{"set-cookie": `(?i)unifises=`},
			Title:  []string{`(?i)UniFi`},
			Body:   []string{`(?i)UniFi Network`, `(?i)ubiquiti`},
		},
		{
			Name: "TP-Link Router", Service: "http",
			Header: map[string]string{"server": `(?i)TP-LINK`, "set-cookie": `(?i)TPLINKID=`},
			Title:  []string{`(?i)TP-LINK`, `(?i)TL-WR`, `(?i)Archer`},
		},
		{
			Name: "D-Link Router", Service: "http",
			Header: map[string]string{"server": `(?i)D-Link`},
			Title:  []string{`(?i)D-Link`, `(?i)DIR-\d`},
			Body:   []string{`(?i)D-Link`},
		},
		{
			Name: "NETGEAR Router", Service: "http",
			Header: map[string]string{"set-cookie": `(?i)XSRF_TOKEN=`},
			Title:  []string{`(?i)NETGEAR`},
			Body:   []string{`(?i)NETGEAR`, `(?i)netgear`},
		},
		{
			Name: "Aruba OS", Service: "http",
			Header: map[string]string{"server": `(?i)Aruba`, "set-cookie": `(?i)Zonename=`},
			Title:  []string{`(?i)Aruba`},
			Body:   []string{`(?i)ArubaOS`, `(?i)Aruba Networks`},
		},
		{
			Name: "F5 BIG-IP", Service: "http",
			Header: map[string]string{
				"set-cookie": `(?i)BIGipServer`,
				// X-WA-Info 的真实取值形如 [Central] / [Distributed]；
				// 这里必须写明取值，不能只写 ".+"（否则任何带该头的响应都命中）。
				"x-wa-info": `(?i)\[(Central|Distributed)\]`,
			},
			Title: []string{`(?i)BIG-IP`},
			Body:  []string{`(?i)BIG-IP`, `/tmui/`},
		},
		{
			Name: "Citrix NetScaler", Service: "http",
			Header: map[string]string{"set-cookie": `(?i)NSC_`},
			Title:  []string{`(?i)NetScaler`, `(?i)Citrix Gateway`},
			Body:   []string{`(?i)NetScaler`, `(?i)Citrix Gateway`, `/vpn/js/gateway_login_view.js`},
		},
		{
			Name: "Huawei eSight", Service: "http", Ports: []int{8080, 8443, 31943},
			Header: map[string]string{"server": `(?i)Huawei-eSight`},
			Title:  []string{`(?i)eSight`},
			Body:   []string{`(?i)eSight`},
		},
		{
			Name: "H3C iMC", Service: "http", Ports: []int{8080, 8443},
			Title: []string{`(?i)H3C iMC`, `(?i)intelligent Management Center`},
			Body:  []string{`(?i)iMC`, `/imc/`},
		},
	}
}

// netRulesSecurity 覆盖安全设备/VPN 网关。
func netRulesSecurity() []Rule {
	return []Rule{
		{
			Name: "Fortinet FortiGate", Service: "http",
			Header: map[string]string{"set-cookie": `(?i)FORTIWAFSID=`},
			Title:  []string{`(?i)FortiGate`},
			Body: []string{
				`(?i)FortiGate`, `(?i)FortiToken`, `(?i)fgt_lang`,
				`/sslvpn/portal`, `(?i)Fortinet`,
			},
		},
		{
			Name: "Palo Alto GlobalProtect", Service: "http",
			Header: map[string]string{"set-cookie": `(?i)PHPSESSID=`},
			Title:  []string{`(?i)GlobalProtect`},
			Body:   []string{`/global-protect/login\.esp`, `(?i)GlobalProtect Portal`, `(?i)Palo Alto Networks`},
		},
		{
			Name: "SonicWall", Service: "http",
			Header: map[string]string{"server": `(?i)SonicWALL`},
			Title:  []string{`(?i)SonicWall`},
			Body:   []string{`(?i)SonicWall`, `/sonicui/`},
		},
		{
			Name: "Check Point Gaia", Service: "http", Ports: []int{443, 4434, 8080},
			Title: []string{`(?i)Check Point`},
			Body:  []string{`(?i)Check Point`, `/Login/Login\.html`},
		},
		{
			Name: "Sangfor SSL VPN", Service: "http",
			Header: map[string]string{"set-cookie": `(?i)TWFID=`},
			Title:  []string{`(?i)Sangfor`},
			Body:   []string{`(?i)Sangfor`, `/por/login_psw\.csp`, `(?i)svpn`},
		},
		{
			Name: "Topsec VPN", Service: "http",
			Header: map[string]string{"server": `(?i)Topsec`},
			Title:  []string{`(?i)Topsec`, `(?i)天融信`},
			Body:   []string{`(?i)Topsec`, `(?i)天融信`},
		},
		{
			Name: "NSFOCUS", Service: "http",
			Header: map[string]string{"server": `(?i)NSFOCUS`},
			Title:  []string{`(?i)NSFOCUS`, `(?i)绿盟`},
			Body:   []string{`(?i)NSFOCUS`, `(?i)绿盟`},
		},
		{
			Name: "360 Wangshen", Service: "http", Ports: []int{443, 8443},
			Header: map[string]string{"server": `(?i)360waf`},
			Title:  []string{`(?i)网神`, `(?i)360网神`},
			Body:   []string{`(?i)网神`, `(?i)360网神`},
		},
		{
			Name: "Array Networks", Service: "http",
			Header: map[string]string{"set-cookie": `(?i)AN_SERVER`},
			Title:  []string{`(?i)Array Networks`},
			Body:   []string{`(?i)Array Networks`, `(?i)arrayos`},
		},
		{
			Name: "Hillstone", Service: "http",
			Header: map[string]string{"server": `(?i)Hillstone`},
			Title:  []string{`(?i)Hillstone`},
			Body:   []string{`(?i)Hillstone`, `(?i)SG-6000`},
		},
		{
			Name: "OpenVPN Web", Service: "http",
			Title: []string{`(?i)OpenVPN`},
			Body:  []string{`/openvpn/`, `(?i)OpenVPN Access Server`, `(?i)openvpn-static`},
		},
		{
			Name: "SoftEther VPN", Service: "http",
			Header: map[string]string{"server": `(?i)SoftEther`},
			Body:   []string{`(?i)SoftEther`, `(?i)vpn gate`, `(?i)SoftEther VPN Server`},
		},
	}
}

// netRulesCamera 覆盖安防摄像头/NVR/DVR。
func netRulesCamera() []Rule {
	return []Rule{
		{
			Name: "Hikvision", Service: "http",
			Title: []string{`(?i)Hikvision`, `(?i)海康威视`},
			Body: []string{
				`/doc/page/login\.asp`, `(?i)Hikvision`, `(?i)hikvision`,
				`(?i)webSocketVideoCtrl`, `(?i)海康威视`,
			},
		},
		{
			Name: "Dahua", Service: "http",
			Title: []string{`(?i)Dahua`, `(?i)大华`},
			Body:  []string{`/current_config/`, `(?i)Dahua`, `(?i)大华`, `(?i)dahua`},
		},
		{
			Name: "Uniview", Service: "http",
			Title: []string{`(?i)Uniview`, `(?i)宇视`},
			Body:  []string{`(?i)Uniview`, `(?i)uniview`, `(?i)宇视`},
		},
		{
			Name: "Axis Camera", Service: "http",
			Header: map[string]string{"server": `(?i)AXIS`},
			Title:  []string{`(?i)AXIS`},
			Body:   []string{`/view/viewer_index\.shtml`, `(?i)AXIS Communications`},
		},
		{
			Name: "TP-Link Camera", Service: "http",
			Title: []string{`(?i)tpCamera`, `(?i)TP-LINK`},
			Body:  []string{`(?i)tpCamera`, `/cgi-bin/luci/`},
		},
		{
			Name: "Foscam", Service: "http",
			Title: []string{`(?i)Foscam`, `(?i)IPCam`},
			Body:  []string{`(?i)Foscam`, `/cgi-bin/CGIProxy\.fcgi`, `(?i)IPCam Client`},
		},
		{
			Name: "Embedded DVR", Service: "http",
			Title: []string{`(?i)DVR`, `(?i)NVR`},
			Body:  []string{`(?i)NetDvr`, `/web/cgi-bin/`, `(?i)Digital Video Recorder`},
		},
	}
}

// netRulesPrinter 覆盖打印机与打印服务器。
func netRulesPrinter() []Rule {
	return []Rule{
		{
			Name: "HP JetDirect", Service: "http",
			Header: map[string]string{"server": `(?i)HP-ChaiSOE`, "set-cookie": `(?i)hp_httpd`},
			Title:  []string{`(?i)HP `, `(?i)JetDirect`},
			Body:   []string{`/hp/device/`, `(?i)HP-ChaiSOE`},
		},
		{
			Name: "Canon Printer", Service: "http",
			Header: map[string]string{"server": `(?i)Canon`},
			Title:  []string{`(?i)Canon`},
			Body:   []string{`(?i)Canon`, `/login\.html`},
		},
		{
			Name: "Epson Printer", Service: "http",
			Header: map[string]string{"server": `(?i)EPSON-HTTP`},
			Title:  []string{`(?i)EPSON`},
			Body:   []string{`(?i)EPSON`, `(?i)EpsonNet`},
		},
		{
			Name: "Xerox Printer", Service: "http",
			Header: map[string]string{"server": `(?i)Xerox`},
			Title:  []string{`(?i)Xerox`},
			Body:   []string{`(?i)Xerox`, `/properties/`},
		},
		{
			Name: "Brother Printer", Service: "http",
			Header: map[string]string{"server": `(?i)Brother`, "set-cookie": `(?i)BPLeAP`},
			Title:  []string{`(?i)Brother`},
			Body:   []string{`(?i)Brother`},
		},
		{
			Name: "IBM Print Server", Service: "http",
			Header: map[string]string{"server": `(?i)IBM_HTTP_Server`},
			Title:  []string{`(?i)Infoprint`},
			Body:   []string{`(?i)Infoprint`},
		},
	}
}

// netRulesOA 覆盖国产 OA/协同办公系统。
func netRulesOA() []Rule {
	return []Rule{
		{
			Name: "Weaver e-cology", Service: "http",
			Header: map[string]string{"set-cookie": `(?i)ecology_`},
			Title:  []string{`(?i)泛微`, `(?i)ecology`},
			Body:   []string{`/wui/`, `(?i)ecology`, `(?i)weaver`},
		},
		{
			Name: "Weaver e-office", Service: "http",
			Title: []string{`(?i)e-office`, `(?i)eoffice`},
			Body:  []string{`/eoffice10/`, `(?i)eoffice`, `(?i)e-office`},
		},
		{
			Name: "Seeyon A8", Service: "http",
			Header: map[string]string{"set-cookie": `(?i)JSESSIONID=`},
			Title:  []string{`(?i)Seeyon`, `(?i)致远`},
			Body:   []string{`/seeyon/`, `(?i)seeyon`, `(?i)致远OA`},
		},
		{
			Name: "Landray EKP", Service: "http",
			Title: []string{`(?i)Landray`, `(?i)蓝凌`},
			Body: []string{
				`/ekp/`, `(?i)landray`, `(?i)蓝凌`,
				`(?i)getAjaxDataServlet`,
			},
		},
		{
			Name: "Tongda OA", Service: "http",
			Title: []string{`(?i)通达`, `(?i)Office Anywhere`},
			Body:  []string{`/ispirit/`, `(?i)Office Anywhere`, `(?i)通达OA`},
		},
		{
			Name: "Huatian OA", Service: "http",
			Header: map[string]string{"server": `(?i)dynamo`},
			Title:  []string{`(?i)华天动力`},
			Body:   []string{`/dynamo/`, `(?i)华天动力`},
		},
	}
}

// netRulesERP 覆盖国产 ERP/财务与国外大型 ERP 套件。
func netRulesERP() []Rule {
	return []Rule{
		{
			Name: "Yonyou NC", Service: "http",
			Header: map[string]string{"set-cookie": `(?i)JSESSIONID=`},
			Title:  []string{`(?i)用友`, `(?i)Yonyou`},
			Body:   []string{`/nc/`, `(?i)yonyou`, `(?i)用友`},
		},
		{
			Name: "Yonyou YonSuite", Service: "http",
			Title: []string{`(?i)YonSuite`},
			Body:  []string{`/yonsuite/`, `(?i)YonSuite`},
		},
		{
			Name: "Yonyou U8", Service: "http",
			Header: map[string]string{"server": `(?i)U8`},
			Title:  []string{`(?i)用友U8`, `(?i)U8 `},
			Body:   []string{`/U8Portal`, `(?i)用友U8`},
		},
		{
			Name: "Kingdee EAS", Service: "http",
			Title: []string{`(?i)Kingdee`, `(?i)金蝶`},
			Body:  []string{`/eas/`, `(?i)kingdee`},
		},
		{
			Name: "Kingdee K3 Cloud", Service: "http",
			Title: []string{`(?i)K3 Cloud`, `(?i)金蝶`},
			Body:  []string{`/K3Cloud/`, `(?i)K3Cloud`},
		},
		{
			Name: "Inspur GS", Service: "http", Ports: []int{8080, 8443},
			Header: map[string]string{"server": `(?i)Inspur`},
			Title:  []string{`(?i)浪潮`, `(?i)Inspur`},
			Body:   []string{`(?i)Inspur`, `(?i)浪潮GS`},
		},
		{
			Name: "Digiwin ERP", Service: "http",
			Title: []string{`(?i)DigiWin`, `(?i)鼎捷`},
			Body:  []string{`/DigiWin/`, `(?i)DigiWin`},
		},
		{
			Name: "SAP NetWeaver", Service: "http",
			Header: map[string]string{"server": `(?i)SAP NetWeaver`},
			Title:  []string{`(?i)SAP NetWeaver`},
			Body:   []string{`/irj/portal`, `(?i)SAP NetWeaver`, `(?i)sap.com/irj`},
		},
		{
			Name: "Oracle EBS", Service: "http",
			Title: []string{`(?i)Oracle E-Business Suite`, `(?i)E-Business Suite`},
			Body:  []string{`/OA_HTML/`, `(?i)Oracle E-Business Suite`},
		},
	}
}

// netRulesMiddleware 覆盖国产中间件与国产/云原生数据库的 Web 与协议特征。
func netRulesMiddleware() []Rule {
	return []Rule{
		{
			Name: "TongWeb", Service: "http",
			Header: map[string]string{"server": `(?i)TongWeb`},
			Body:   []string{`(?i)TongWeb`, `(?i)tongweb`},
		},
		{
			Name: "Apusic", Service: "http",
			Header: map[string]string{"server": `(?i)apusic`},
			Body:   []string{`(?i)Apusic`},
		},
		{
			Name: "BES Application Server", Service: "http",
			Header: map[string]string{"server": `(?i)BES/`},
			Body:   []string{`(?i)BES Application Server`},
		},
		{
			Name: "InforSuite", Service: "http",
			Header: map[string]string{"server": `(?i)InforSuite`},
			Body:   []string{`(?i)InforSuite`, `(?i)中创中间件`},
		},
		{
			Name: "Dameng DB", Service: "http",
			Header: map[string]string{"server": `(?i)DM8`, "set-cookie": `(?i)dm8_`},
			Title:  []string{`(?i)达梦`},
			Body:   []string{`(?i)达梦`, `(?i)DM8`, `(?i)Dameng`},
		},
		{
			Name: "KingBase", Service: "http",
			Header: map[string]string{"server": `(?i)KingBase`},
			Title:  []string{`(?i)KingbaseES`, `(?i)人大金仓`},
			Body:   []string{`(?i)KingbaseES`, `(?i)人大金仓`},
		},
		{
			Name: "Shentong DB", Service: "http",
			Title: []string{`(?i)神通数据库`, `(?i)OSCAR`},
			Body:  []string{`(?i)神通数据库`, `(?i)ShenTong`, `(?i)OSCAR`},
		},
		{
			Name: "GBase", Service: "http",
			Header: map[string]string{"server": `(?i)GBase`},
			// 注意：小写化的 "kingbase" 里包含子串 "gbase"，
			// 所以正文只认 "GBase 8" / 厂商中文名，不能只认 GBase 这个单词。
			Title: []string{`(?i)GBase`},
			Body:  []string{`(?i)GBase 8`, `(?i)南大通用`},
		},
		{
			Name: "OceanBase", Service: "http",
			Title: []string{`(?i)OceanBase`},
			Body:  []string{`(?i)OceanBase`, `(?i)OBShell`, `(?i)obproxy`, `(?i)OB-`},
		},
		{
			Name: "TiDB", Service: "http", Ports: []int{10080, 2379, 4000},
			Header: map[string]string{"server": `(?i)TiDB`},
			Title:  []string{`(?i)TiDB`},
			Body:   []string{`(?i)TiDB`, `(?i)TiKV`, `(?i)pd-server`},
		},
		{
			Name: "PolarDB", Service: "http",
			Header: map[string]string{"x-powered-by": `(?i)PolarDB`},
			Title:  []string{`(?i)PolarDB`},
			Body:   []string{`(?i)PolarDB`},
		},
	}
}

// netRulesOps 覆盖网络管理/运维审计平台。
func netRulesOps() []Rule {
	return []Rule{
		{
			Name: "Cacti", Service: "http",
			Title: []string{`(?i)Cacti`},
			Body:  []string{`(?i)cacti`, `/cacti/`, `(?i)CactiEZ`},
		},
		{
			Name: "SolarWinds", Service: "http",
			Header: map[string]string{"set-cookie": `(?i)SolarWinds`},
			Title:  []string{`(?i)SolarWinds`, `(?i)Orion`},
			Body:   []string{`(?i)SolarWinds`, `(?i)Orion/`},
		},
		{
			Name: "PRTG", Service: "http", Ports: []int{8080, 8443},
			Header: map[string]string{"server": `(?i)PRTG`},
			Title:  []string{`(?i)PRTG`},
			Body:   []string{`(?i)PRTG`, `(?i)Paessler`},
		},
		{
			Name: "WhatsUp Gold", Service: "http",
			Title: []string{`(?i)WhatsUp`},
			Body:  []string{`(?i)WhatsUp Gold`, `(?i)WhatsUpGold`, `(?i)NmConsole`},
		},
		{
			Name: "ManageEngine", Service: "http",
			Header: map[string]string{"set-cookie": `(?i)JSESSIONID=`},
			Title:  []string{`(?i)ManageEngine`, `(?i)OpManager`, `(?i)ServiceDesk Plus`},
			Body:   []string{`(?i)ManageEngine`, `(?i)OpManager`, `(?i)adventnet`},
		},
		{
			Name: "Zoho Corp", Service: "http",
			Header: map[string]string{"set-cookie": `(?i)JSESSIONID_=`},
			Title:  []string{`(?i)Zoho`},
			Body:   []string{`(?i)Zoho Corporation`},
		},
		{
			Name: "Ruijie RIIL", Service: "http", Ports: []int{8080, 8443},
			Title: []string{`(?i)RIIL`, `(?i)锐捷`},
			Body:  []string{`(?i)RIIL`},
		},
		{
			Name: "JumpServer", Service: "http",
			Header: map[string]string{"server": `(?i)JumpServer`},
			Title:  []string{`(?i)JumpServer`},
			Body:   []string{`/core/auth/login`, `(?i)JumpServer`},
		},
		{
			Name: "Teleport", Service: "http",
			Title: []string{`(?i)Teleport`},
			Body:  []string{`/webapi/ping`, `(?i)Teleport`},
		},
		{
			Name: "Qizhi Bastion", Service: "http", Ports: []int{443, 8443},
			Title: []string{`(?i)齐治`, `(?i)Shterm`},
			Body:  []string{`(?i)齐治`, `(?i)shterm`},
		},
		{
			Name: "Yunbox", Service: "http",
			Title: []string{`(?i)行云管家`},
			Body:  []string{`(?i)行云管家`, `(?i)cloudbility`},
		},
	}
}

// netRulesStorage 覆盖存储/备份系统。
func netRulesStorage() []Rule {
	return []Rule{
		{
			Name: "Synology DSM", Service: "http",
			Title: []string{`(?i)Synology`, `(?i)DSM`},
			Body:  []string{`/webman/`, `(?i)Synology DiskStation`, `(?i)DSM `},
		},
		{
			Name: "QNAP QTS", Service: "http", Ports: []int{8080, 443, 8443},
			Title: []string{`(?i)QNAP`, `(?i)QTS`},
			Body:  []string{`(?i)QNAP`, `(?i)QTS`, `/cgi-bin/authLogin\.cgi`},
		},
		{
			Name: "TrueNAS", Service: "http",
			Title: []string{`(?i)TrueNAS`, `(?i)FreeNAS`},
			Body:  []string{`(?i)TrueNAS`, `(?i)FreeNAS`, `(?i)freenas`},
		},
		{
			Name: "Huawei OceanStor", Service: "http", Ports: []int{8088, 8443},
			Title: []string{`(?i)OceanStor`, `(?i)DeviceManager`},
			Body:  []string{`(?i)OceanStor`, `(?i)DeviceManager`, `(?i)华为存储`},
		},
		{
			Name: "EMC Unisphere", Service: "http", Ports: []int{443, 8443},
			Title: []string{`(?i)Unisphere`},
			Body:  []string{`(?i)Unisphere`, `(?i)EMC Corporation`},
		},
		{
			Name: "NetApp ONTAP", Service: "http",
			Title: []string{`(?i)NetApp`, `(?i)ONTAP`},
			Body:  []string{`(?i)NetApp`, `(?i)ONTAP`, `(?i)System Manager`},
		},
		{
			Name: "Ceph Dashboard", Service: "http",
			Title: []string{`(?i)Ceph`},
			Body:  []string{`(?i)Ceph Dashboard`, `(?i)ceph\.js`, `(?i)radosgw`},
		},
		{
			Name: "Veeam", Service: "http", Ports: []int{9419, 9443},
			Title: []string{`(?i)Veeam`},
			Body:  []string{`(?i)Veeam Backup`, `(?i)Veeam`},
		},
	}
}

// netRulesIndustrial 覆盖少量工控特征。
//
// 这里刻意只认端口：S7 与 Modbus 的 payload 无法在离线环境验证，
// 写错正则的代价是长期误报；纯端口规则已由引擎自动降级为 low 置信度。
func netRulesIndustrial() []Rule {
	return []Rule{
		{
			Name: "Siemens S7 PLC", Service: "s7", Ports: []int{102}, Confidence: "low",
		},
		{
			Name: "Modbus TCP", Service: "modbus", Ports: []int{502}, Confidence: "low",
		},
		{
			Name: "SNMP", Service: "snmp", Ports: []int{161, 162}, Confidence: "low",
		},
	}
}
