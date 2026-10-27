# 应用锁+ 重构版 (AppLock+ Refactored) v0.4.2

基于 [tien0246/ProtectedApp](https://github.com/tien0246/ProtectedApp) 分析重构的**单应用注入式**应用锁 dylib。
适用于 **TrollFools / JailFools** 按应用注入工作流（无越狱/隐藏越狱环境，无需 CydiaSubstrate）。

---

## 一、原版问题分析

对市面流传的 `应用锁+_0.1-1 dylib`（Hikari LLVM 混淆、由 `iosrxwy` 用 Xcode 构建的魔改版，
类结构：`ProtectedApp` + `authenticateWithBiometrics` + `unlockApp` + `lockoutEndTime` 等）与作者仓库源码
对照后，确认以下缺陷：

| # | 缺陷 | 严重性 |
|---|------|--------|
| 1 | **面容 ID 点「取消」即可进入应用**——`evaluatePolicy` 的回调把失败/取消也当作成功放行（或以 `biometricAttempted` 标记"已尝试过"后放行），锁定窗口被直接关闭 | 致命 |
| 2 | **锁定状态下快速返回可直接解锁**——`handleWillEnterForeground` 只比较"离开时长 < timeout"就隐藏锁定窗口，即使此前从未验证通过 | 严重 |
| 3 | **密码明文存储**——`NSUserDefaults` 的 `com.tien0246.ProtectedApp → passcode` 键，任何有文件系统权限的进程可直接读取 | 严重 |
| 4 | **首次默认密码 0000** 且无强制修改流程（README 公开写明），人人皆知 | 严重 |
| 5 | **无真正设置面板**——设置藏在"三指双击"手势里（魔改版还加了双指双击打开推广 Telegram 的行为），无法发现，也无二级密码选项 | 中 |
| 6 | 只 hook 一次 `makeKeyAndVisible`，锁定状态与解锁状态判断交织，边界情况多 | 中 |

> 注：原仓库 README 中的设置入口是 **三指双击（3 fingers twice）**，仅限锁定界面，且没有任何提示，
> 这就是"感觉没有设置面板"的原因；魔改版在此基础上并未提供二级密码功能。

## 二、重构版改进

- **修复绕过漏洞（核心）**：面容/触控 ID 验证的 `reply:` 回调里，`success == NO`（包括用户点取消、
  系统取消、识别失败、生物识别被锁定）一律**停留在密码键盘**，绝不放行。Face ID 只是"快捷方式"，
  密码才是兜底 —— 无法绕过。
- **首次启动强制设置 6 位应用锁密码**，不可跳过（替代默认 0000）。
- **完整设置面板**（中文）：
  - 面容 / 触控 ID 解锁开关（自动检测设备支持情况）
  - 重新锁定时机：立即 / 15 秒 / 1 分钟 / 5 分钟
  - 修改应用锁密码（需验证当前密码）
- **设置入口两个**：锁定界面右上角齿轮（需先验证密码，只进设置不解锁应用）；应用内**双指双击**（已解锁状态直达）。
  v0.4.1 起由三指双击改为**双指双击**——三指手势与 iOS 13+ 系统文本编辑手势冲突且时序难按，双指更灵敏。
- **安全存储**：密码以 `PBKDF2-SHA256`（2 万次迭代 + 16 字节随机盐）哈希，优先存 **Keychain**，
  Keychain 不可用时退回 `NSUserDefaults`（仍是哈希，非明文）；比较采用恒定时间算法。
- **旧版无缝迁移**：自动读取旧版明文密码（`com.tien0246.ProtectedApp`）→ 转哈希存储 → 删除明文，无需重设。
- **防后台快照泄露**：`willResignActive` 立即用高窗口级模糊遮盖（App 切换器缩略图看不到应用内容）。
- **指数冷却**：连续输错 5 次起，冷却 1→2→4→8…分钟（上限 17 小时），状态持久化，**杀进程不重置**。
- **现代应用兼容**：`UIWindowScene` 适配（iOS 13+ / SwiftUI 应用），恒定时间比较，SF Symbols 图标，触感反馈。
- **移除**魔改版的双指双击打开 Telegram 推广行为。

## 三、目录结构

```
applock-plus/
├── Tweak.m           # 全部逻辑（单文件，ARC，纯 ObjC runtime swizzle，无 Logos/substrate 依赖）
├── Makefile          # theos 构建配置 (library 方式, arm64, iOS 14+)
└── README.md
```

> 注意：本版本**不以 tweak (CydiaSubstrate) 方式构建**。原 tweak 版在 TrollFools / JailFools
> 等无 substrate 的单应用注入环境中会因 dyld 无法解析
> `/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate` 依赖而**完全不加载**
> （表现为注入后毫无动静）。现改为与 NTQQ_AntiRecall 等免 substrate 插件相同的方案：
> 纯 ObjC runtime `method_setImplementation` swizzle + 通知兜底引导，仅依赖系统框架。

## 四、构建

需要 [theos](https://theos.dev) 环境（macOS / Linux / WSL2 均可）：

```bash
cd applock-plus
make FINALPACKAGE=1
# 产物: .theos/obj/AppLockPlus.dylib (arm64, ldid 已签名)
```

产物特征（`otool -L` 可自行验证）：

- install name 为 `@rpath/AppLockPlus.dylib`；
- 仅链接系统框架（UIKit / Foundation / LocalAuthentication / Security / QuartzCore / libobjc），
  **无 CydiaSubstrate**；
- 含 `__mod_init_func` 构造函数入口，dylib 一被加载即完成 swizzle。

> 无法在 Windows 直接编译 iOS dylib；Windows 下可用 WSL2 安装 theos，一次构建约 1 分钟。

## 五、注入（TrollFools / JailFools）

1. 用 **TrollFools** 或 **JailFools** 将 `AppLockPlus.dylib` 注入目标应用（如 QQ）；
2. 无需任何 substrate 兼容层——dylib 自带 hook 机制，注入即生效；
3. 冷启动目标应用即弹出锁定界面：首次进入**强制设置 6 位密码**流程；
4. **Face ID 说明**：Face ID 弹窗要求宿主应用 `Info.plist` 声明 `NSFaceIDUsageDescription`。
   QQ 已声明（支持面容登录），因此面容解锁可用；其他未声明的应用中本 tweak 会自动禁用
   Face ID（不会崩溃），仅用密码解锁。如需为某应用启用：重签 IPA 时在 `Info.plist` 添加
   `NSFaceIDUsageDescription = "用于解锁应用"`。
5. 若注入后仍无反应，请确认注入的是**新版 dylib**（旧 tweak 版含 substrate 依赖，不会加载），
   并重启一次目标应用。

## 六、使用说明

| 操作 | 说明 |
|------|------|
| 首次打开应用 | 强制设置 6 位应用锁密码（两遍确认），随后询问是否启用面容 ID；**设置完成后直接进入应用** |
| 打开应用 | 出现锁屏后**默认延迟 2 秒**自动刷脸（可在设置中改为立即 / 5 秒 / 关闭）；延迟期间可输入密码或点齿轮；面容取消/失败一律停留密码键盘 |
| 锁屏齿轮（右上角） | 验证后进入设置；**关闭设置面板后直接进入应用**（无需再输一次密码） |
| 应用内双指双击 | 已解锁状态下，在应用内任意页面**两根手指连续轻点两次**直接打开设置，关闭后回到应用。手势挂载到所有可见主层级 window（NTQQ 多 window 架构下仅挂 key window 会失效），不与系统三指文本编辑手势冲突；可在设置 → 解锁方式 → "双指双击呼出设置面板" 关闭 |
| 自动验证面容 | 设置 → 解锁方式 → 自动验证面容：关闭 / 立即 / 延迟 2 秒 / 延迟 5 秒 |
| 双指双击手势 | 设置 → 解锁方式 → "双指双击呼出设置面板" 开关（默认开启），关闭后彻底移除应用内手势 |
| 修改密码 | 设置 → 密码 → 修改应用锁密码：**自带数字键盘三步流程**（当前密码 → 新密码 → 确认），输错当前密码同样计入冷却 |
| 重新锁定 | 退出应用后台超过设定时长（默认 15 秒）后重新进入时锁定；设为"立即锁定"时退后台即进入完整锁定态 |
| 输错密码 | 5 次后开始 1、2、4、8…分钟指数冷却，重启应用也不会重置计数 |
| 忘记密码 | 锁屏底部"忘记密码？"→ 验证设备所有者身份（设备锁屏密码/系统面容）→ **直接在锁屏界面内出现"重置应用锁/取消"按钮**（不依赖系统弹窗，无卡死竞态）→ 确认后清除 Keychain 记录与全部偏好，回到首次设置流程。设备未设锁屏密码时跳过所有者验证直接进入确认（有风险，建议始终设置设备密码） |

> **设置入口不在 QQ 自身的"设置"页面里**（本插件无法往 QQ 原生设置页插菜单）：
> 入口只有两个——锁定界面右上角**齿轮图标**、应用内**双指双击**（v0.4.0 及更早版本为三指双击）。

## 七、安全边界（务必了解）

这类"应用内注入"方案能防的是**随手借用手机的人**直接打开受保护应用。它不能防御以下情况
（这一点与 BioProtect 等全局方案、以及原版完全相同）：

- 有文件系统访问权的进程（Filza 等）可以直接**删除 dylib 注入记录**或修改应用的沙盒偏好；
- 冷却计数和"重新锁定时机"存于应用沙盒的 `NSUserDefaults`，可被手工改写；
- 已 root 且了解 tweak 原理的人可以反注入。

> 重置入口的门槛：`LAPolicyDeviceOwnerAuthentication` 要求设备锁屏密码或系统面容验证，
> 借用手机的人无法通过；但若设备**未设置锁屏密码**，则任何持有手机者都可重置。
> 另外注意：删除 QQ 重装能清空沙盒设置（冷却计数等），但 Keychain 中的密码记录会保留，
> 该路径既重置不了密码，还会丢失 QQ 本地数据。

要提升到防文件系统攻击的强度，需要把冷却状态与配置移入 Keychain（服务名与密码不同），
或配合越狱隐藏方案使用——如有需要可在此基础上继续扩展。

## 八、设备兼容性（Touch ID / iPad）

本插件**自动适配**面容 ID 与触控 ID，无需拆分版本：

- **触控 ID 设备**（iPhone 8/SE 及更早、Touch ID 版 iPad）：检测到 `LABiometryTypeTouchID` 后，
  锁屏按钮、文案、首次设置询问、设备所有者验证（重置门槛）全部自动切换为指纹流程；
  且触控 ID **不需要**宿主应用声明 `NSFaceIDUsageDescription`（该要求仅针对面容 ID），
  可用性比面容更宽；
- **iPad**：锁定界面自适应布局；设置面板中的选择弹层已指定 popover 锚点（iPad 上
  ActionSheet 不指定锚点会直接崩溃，v0.3.3 已修复）；
- 面容/触控不可用或被禁用时，一律回退数字键盘，功能完整不受影响。

## 九、与原版的行为差异速查

| 场景 | 原魔改版 | 重构版 |
|------|----------|--------|
| Face ID 弹窗点取消 | 直接进入应用 ❌ | 停留密码键盘 ✅ |
| 锁定时快速返回 | 可能直接解锁 ❌ | 保持锁定 ✅ |
| 首次使用 | 默认 0000 | 强制自设 6 位密码 ✅ |
| 密码存储 | NSUserDefaults 明文 | Keychain + PBKDF2 哈希 ✅ |
| 设置入口 | 无提示的三指双击（英文弹窗） | 锁屏齿轮 + 双指双击，全中文面板 ✅ |

## 十、许可与致谢

- 本项目基于 **[tien0246/ProtectedApp](https://github.com/tien0246/ProtectedApp)** 的思路与结构分析重构而来，
  感谢原作者的开源工作；重构版修复了原版（及其流传魔改版）的多项安全缺陷，详见文首对比表。
- 本项目以 **[MIT License](LICENSE)** 发布； LICENSE 文件内附对原作者的 Attribution 声明。
- 面容 ID / 触控 ID、UIKit、LocalAuthentication 等均为 Apple Inc. 的商标/技术。
| 二级密码 | 无 | 有（Face ID 失败兜底 + 可独立解锁） ✅ |
| 旧密码迁移 | — | 自动转换明文为哈希 ✅ |
| 推广行为 | 双指双击打开 Telegram | 已移除 ✅ |
