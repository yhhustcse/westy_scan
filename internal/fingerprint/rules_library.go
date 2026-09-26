package fingerprint

// 扩展规则库（M7「弹药补充」）。
//
// 为什么单独拆文件：内置规则原先只有 48 条，做资产测绘时常出现"认得出来是 HTTP，
// 但认不出是什么产品"。规则库按主题分文件维护，便于：
//   - 大库与小库分开评审（一条规则写错就是长期误报，见 M2 的 `.*` 事故）；
//   - 后续接入外部规则源时按来源替换/停用（Rule.Enabled 支持显式停用）。
//
// 质量门槛（写规则时务必遵守，rules_library_*_test.go 会强制校验）：
//  1. 每条规则必须能回答"什么样的真实响应会命中它"，并把该样本写进测试；
//  2. 禁止裸 `.*`：正则里必须有具体字面量；header 值正则用 `.+` 而不是 `.*`，
//     否则空响应头也会命中（M2 踩过）；
//  3. 大小写不敏感要显式写 `(?i)`；
//  4. **只用 RE2 支持的语法**：不支持 lookahead/lookbehind/反向引用（M4 踩过）；
//  5. 能用 Ports 收敛就收敛，减少跨服务误报。
func libraryRules() []Rule {
	out := make([]Rule, 0, 256)
	out = append(out, libraryRulesApp()...)
	out = append(out, libraryRulesNet()...)
	return out
}
