package poc

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"westy_scan/internal/jsonutil"
)

// templates/*.json 是内置模板（随二进制分发，保证开箱即用且离线可用）。
//
//go:embed templates/*.json
var builtinFS embed.FS

// LoadOptions 控制模板加载。
type LoadOptions struct {
	IncludeBuiltin bool     // 是否加载内置模板
	Paths          []string // 模板文件或目录（.json / .yaml / .yml）
	Tags           []string // 只保留带这些标签的模板（空表示不限）
	Severity       string   // 只保留不低于该级别的模板
	MaxTemplates   int
}

// Load 加载并**编译期校验**全部模板。
//
// 任何一个模板非法都直接报错，而不是运行时静默跳过 ——
// "模板写错了但没报错、只是再也不命中"是漏洞扫描器最危险的失败模式。
func Load(opt LoadOptions) ([]*Template, error) {
	var loaded []*Template

	if opt.IncludeBuiltin {
		entries, err := fs.ReadDir(builtinFS, "templates")
		if err != nil {
			return nil, fmt.Errorf("读取内置模板失败: %w", err)
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			data, err := builtinFS.ReadFile("templates/" + name)
			if err != nil {
				return nil, err
			}
			tpls, err := parseJSONTemplates(data)
			if err != nil {
				return nil, fmt.Errorf("内置模板 %s 非法: %w", name, err)
			}
			for _, tpl := range tpls {
				tpl.Source = "builtin:" + name
				loaded = append(loaded, tpl)
			}
		}
	}

	for _, path := range opt.Paths {
		tpls, err := loadPath(path)
		if err != nil {
			return nil, err
		}
		loaded = append(loaded, tpls...)
	}

	// 去重（按 ID，后加载的覆盖先加载的，便于用外置模板修正内置模板）
	//
	// 但"两个内置文件定义了同一个 id"一定是写错了：两个批次各自以为是自己的模板，
	// 静默覆盖会让其中一条永远不生效、而且没有任何提示 —— 所以这种覆盖直接报错。
	merged := map[string]*Template{}
	order := make([]string, 0, len(loaded))
	for _, tpl := range loaded {
		if prev, ok := merged[tpl.ID]; ok {
			if err := checkIDCollision(prev, tpl); err != nil {
				return nil, err
			}
		} else {
			order = append(order, tpl.ID)
		}
		merged[tpl.ID] = tpl
	}

	out := make([]*Template, 0, len(order))
	for _, id := range order {
		tpl := merged[id]
		if err := Validate(tpl); err != nil {
			return nil, fmt.Errorf("模板 %s（来源 %s）校验失败: %w", tpl.ID, tpl.Source, err)
		}
		if !matchTags(tpl, opt.Tags) {
			continue
		}
		if !SeverityAtLeast(tpl.Info.Severity, opt.Severity) {
			continue
		}
		out = append(out, tpl)
		if opt.MaxTemplates > 0 && len(out) >= opt.MaxTemplates {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("没有可用模板（内置=%v 路径=%v 标签=%v 级别=%q）",
			opt.IncludeBuiltin, opt.Paths, opt.Tags, opt.Severity)
	}
	return out, nil
}

func loadPath(path string) ([]*Template, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("模板路径不可用 %s: %w", path, err)
	}
	if !info.IsDir() {
		return parseTemplateFile(path)
	}

	var out []*Template
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".json", ".yaml", ".yml":
			tpls, err := parseTemplateFile(p)
			if err != nil {
				return err
			}
			out = append(out, tpls...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("目录 %s 下没有找到 .json/.yaml/.yml 模板", path)
	}
	return out, nil
}

// parseTemplateFile 支持"单模板对象"与"模板数组"两种文件形态。
func parseTemplateFile(path string) ([]*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tpls []*Template
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		tpls, err = parseJSONTemplates(data)
	case ".yaml", ".yml":
		tpl, yerr := parseYAMLTemplate(data)
		err = yerr
		if err == nil {
			tpls = []*Template{tpl}
		}
	default:
		return nil, fmt.Errorf("不支持的模板格式: %s", path)
	}
	if err != nil {
		return nil, fmt.Errorf("解析模板 %s 失败: %w", path, err)
	}
	for _, tpl := range tpls {
		tpl.Source = path
	}
	return tpls, nil
}

// parseJSONTemplates 兼容 {"id":...} 与 [{...},{...}] 两种根结构。
func parseJSONTemplates(data []byte) ([]*Template, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		var list []Template
		if err := jsonutil.Unmarshal(data, &list); err != nil {
			return nil, err
		}
		out := make([]*Template, 0, len(list))
		for i := range list {
			out = append(out, &list[i])
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("模板数组为空")
		}
		return out, nil
	}
	var tpl Template
	if err := jsonutil.Unmarshal(data, &tpl); err != nil {
		return nil, err
	}
	return []*Template{&tpl}, nil
}

// parseYAMLTemplate 走 nuclei YAML 子集适配器：先解析成通用结构，再转成 Template。
func parseYAMLTemplate(data []byte) (*Template, error) {
	doc, err := ParseYAMLSubset(string(data))
	if err != nil {
		return nil, err
	}
	normalized, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var tpl Template
	if err := json.Unmarshal(normalized, &tpl); err != nil {
		return nil, fmt.Errorf("YAML 结构与模板字段不匹配: %w", err)
	}
	return &tpl, nil
}

func matchTags(tpl *Template, want []string) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		w = strings.ToLower(strings.TrimSpace(w))
		for _, tag := range tpl.Info.Tags {
			if strings.EqualFold(strings.TrimSpace(tag), w) {
				return true
			}
		}
		if strings.EqualFold(tpl.ID, w) {
			return true
		}
	}
	return false
}

// checkIDCollision 判断同 id 的两条模板是否属于"不允许的覆盖"。
//
// 允许：外置覆盖内置、外置之间后者覆盖前者（便于用外置模板修正内置模板）。
// 不允许：两个**内置**文件定义了同一个 id —— 规则库分成多个批次维护时，
// 这是最容易犯又最难发现的错：两条模板都在库里，但只有一条生效。
func checkIDCollision(prev, cur *Template) error {
	if strings.HasPrefix(prev.Source, "builtin:") && strings.HasPrefix(cur.Source, "builtin:") {
		return fmt.Errorf("模板 id 重复: %s（%s 与 %s）—— 内置模板之间不允许重名，否则其中一条永远不会生效",
			cur.ID, prev.Source, cur.Source)
	}
	return nil
}

// knownVars 是引擎能提供的全部变量（大小写不敏感）。
func knownVars() map[string]bool {
	names := []string{
		"BaseURL", "RootURL", "Hostname", "Host", "Port", "Scheme", "Path", "IP", "File",
		"randstr", "randstr_1", "randstr_2", "randstr_3",
		"oob", "oob_url", "oob_host",
	}
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[strings.ToLower(n)] = true
	}
	return m
}

// allowedMethods 是允许的 HTTP 方法。
// 只允许只读方法；POST/PUT/PATCH/DELETE 必须显式声明 intrusive:true，
// 并由执行端用 -allow-intrusive 二次放行。
var allowedMethods = map[string]bool{
	"GET": true, "HEAD": true, "OPTIONS": true,
	"POST": true, "PUT": true, "PATCH": true, "DELETE": true,
}

var readOnlyMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}

// destructivePatterns 是"明显会改数据/搞破坏"的关键字。
// 命中的模板必须显式声明 intrusive:true —— 这是防止模板库被误用的最后一道闸门。
var destructivePatterns = []string{
	"drop table", "delete from", "truncate table", "shutdown", "rm -rf",
	"mkfs", "format c:", "drop database", "--dump", "into outfile",
}

// Validate 做编译期校验。
func Validate(tpl *Template) error {
	if tpl == nil {
		return fmt.Errorf("空模板")
	}
	if strings.TrimSpace(tpl.ID) == "" {
		return fmt.Errorf("缺少 id")
	}
	if strings.TrimSpace(tpl.Info.Name) == "" {
		tpl.Info.Name = tpl.ID // 允许省略，用 id 兜底
	}
	if len(tpl.HTTP) == 0 {
		return fmt.Errorf("缺少 http 段")
	}
	if tpl.Info.Severity != "" && severityRank(tpl.Info.Severity) == 0 {
		return fmt.Errorf("非法 severity %q（可选 info/low/medium/high/critical）", tpl.Info.Severity)
	}
	if tpl.Info.Confidence != "" {
		switch strings.ToLower(tpl.Info.Confidence) {
		case "high", "medium", "low":
		default:
			return fmt.Errorf("非法 confidence %q（可选 high/medium/low）", tpl.Info.Confidence)
		}
	}
	if c := strings.ToLower(strings.TrimSpace(tpl.MatchersCondition)); c != "" && c != "and" && c != "or" {
		return fmt.Errorf("非法 matchers-condition %q", tpl.MatchersCondition)
	}

	known := knownVars()
	for i := range tpl.HTTP {
		req := &tpl.HTTP[i]
		req.Method = strings.ToUpper(strings.TrimSpace(req.Method))
		if req.Method == "" {
			req.Method = "GET"
		}
		if !allowedMethods[req.Method] {
			return fmt.Errorf("第 %d 个请求使用了不支持的方法 %q", i+1, req.Method)
		}
		if !readOnlyMethods[req.Method] && !tpl.Intrusive {
			return fmt.Errorf("第 %d 个请求使用了 %s 方法：写操作类请求必须显式声明 \"intrusive\": true，并用 -allow-intrusive 执行",
				i+1, req.Method)
		}
		if len(req.Path) == 0 {
			return fmt.Errorf("第 %d 个请求缺少 path", i+1)
		}
		if len(req.Matchers) == 0 {
			return fmt.Errorf("第 %d 个请求缺少 matchers（没有匹配器的模板只会产生噪声）", i+1)
		}
		if c := strings.ToLower(strings.TrimSpace(req.MatchersCondition)); c != "" && c != "and" && c != "or" {
			return fmt.Errorf("第 %d 个请求的 matchers-condition 非法: %q", i+1, req.MatchersCondition)
		}

		// 变量检查：未提供的变量会被原样发出，属于静默失效，必须在加载期拦下
		var texts []string
		texts = append(texts, req.Path...)
		texts = append(texts, req.Body)
		for k, v := range req.Headers {
			texts = append(texts, k, v)
		}
		for _, m := range req.Matchers {
			texts = append(texts, m.Words...)
			texts = append(texts, m.Regex...)
			for k, v := range m.Headers {
				texts = append(texts, k, v)
			}
		}
		for _, e := range req.Extractors {
			texts = append(texts, e.Regex...)
		}
		for _, text := range texts {
			for _, name := range UnknownVars(text, nil) {
				if !known[strings.ToLower(name)] {
					return fmt.Errorf("第 %d 个请求引用了未知变量 {{%s}}", i+1, name)
				}
			}
		}

		for j, m := range req.Matchers {
			if err := validateMatcher(m); err != nil {
				return fmt.Errorf("第 %d 个请求的第 %d 个匹配器非法: %w", i+1, j+1, err)
			}
		}
		for j, e := range req.Extractors {
			if err := validateExtractor(e); err != nil {
				return fmt.Errorf("第 %d 个请求的第 %d 个提取器非法: %w", i+1, j+1, err)
			}
		}

		// 破坏性关键字检查
		if !tpl.Intrusive {
			blob := strings.ToLower(strings.Join(req.Path, " ") + " " + req.Body)
			for _, pat := range destructivePatterns {
				if strings.Contains(blob, pat) {
					return fmt.Errorf("模板包含破坏性关键字 %q：必须显式声明 \"intrusive\": true 并用 -allow-intrusive 执行", pat)
				}
			}
		}
	}
	return nil
}

func validateMatcher(m Matcher) error {
	switch strings.ToLower(strings.TrimSpace(m.Type)) {
	case "status":
		if len(m.Status) == 0 {
			return fmt.Errorf("status 匹配器缺少 status")
		}
		for _, code := range m.Status {
			if code < 100 || code > 599 {
				return fmt.Errorf("非法状态码 %d", code)
			}
		}
	case "word":
		if len(m.Words) == 0 {
			return fmt.Errorf("word 匹配器缺少 words")
		}
	case "regex":
		if len(m.Regex) == 0 {
			return fmt.Errorf("regex 匹配器缺少 regex")
		}
		for _, p := range m.Regex {
			if _, err := compileCached(p); err != nil {
				return fmt.Errorf("正则非法 %q: %w（注意：Go 使用 RE2 语法，不支持 lookahead/lookbehind/反向引用等 PCRE 特性，"+
					"从 nuclei/PCRE 模板移植时需要改写）", p, err)
			}
		}
	case "size":
		if len(m.Size) == 0 {
			return fmt.Errorf("size 匹配器缺少 size")
		}
		for _, s := range m.Size {
			if s < 0 {
				return fmt.Errorf("非法长度 %d", s)
			}
		}
	case "header":
		if len(m.Headers) == 0 {
			return fmt.Errorf("header 匹配器缺少 headers")
		}
		for name, p := range m.Headers {
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("header 匹配器存在空的头名")
			}
			if strings.TrimSpace(p) == "" {
				continue
			}
			if _, err := compileCached(p); err != nil {
				return fmt.Errorf("头 %s 的正则非法 %q: %w", name, p, err)
			}
		}
	case "title":
		if len(m.Regex) == 0 && len(m.Words) == 0 {
			return fmt.Errorf("title 匹配器需要 regex 或 words")
		}
	case "":
		return fmt.Errorf("缺少 type")
	default:
		return fmt.Errorf("不支持的匹配器类型 %q（可选 status/word/regex/size/header/title）", m.Type)
	}
	if c := strings.ToLower(strings.TrimSpace(m.Condition)); c != "" && c != "and" && c != "or" {
		return fmt.Errorf("非法 condition %q", m.Condition)
	}
	return nil
}

func validateExtractor(e Extractor) error {
	switch strings.ToLower(strings.TrimSpace(e.Type)) {
	case "regex":
		if len(e.Regex) == 0 {
			return fmt.Errorf("regex 提取器缺少 regex")
		}
		for _, p := range e.Regex {
			if _, err := compileCached(p); err != nil {
				return fmt.Errorf("正则非法 %q: %w", p, err)
			}
		}
	case "kval":
		if len(e.KVal) == 0 {
			return fmt.Errorf("kval 提取器缺少 kval")
		}
	case "json":
		if len(e.JSON) == 0 {
			return fmt.Errorf("json 提取器缺少 json 路径")
		}
	case "":
		return fmt.Errorf("缺少 type")
	default:
		return fmt.Errorf("不支持的提取器类型 %q（可选 regex/kval/json）", e.Type)
	}
	return nil
}
