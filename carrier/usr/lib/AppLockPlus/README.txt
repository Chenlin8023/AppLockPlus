AppLock+ 重构版 v0.4.2 —— 按应用注入式应用锁
================================================================

这个包里只有一个东西：AppLockPlus.dylib（外加本说明）。
它不是 SpringBoard 全局插件，装完不会自动生效。用途是：

    把 dylib 注入到你指定的某一个 App 里，让那个 App 单独上锁。

适用场景
--------
- 只想给个别 App（相册、微信、QQ、银行类）上锁；
- 目标 App 会检测越狱 / 反注入，全局 tweak 注入不进去；
- 不想因为一个锁就改动系统里所有应用。

安装后文件位置
--------------
    /var/mobile/Documents/AppLockPlus/AppLockPlus.dylib

也可以直接从本 deb 里取：用 Debs 导出本包，或 Filza 打开
/var/mobile/Documents/AppLockPlus/ 复制出来。

使用步骤
--------
1. 取得 AppLockPlus.dylib（见上）。
2. 用 TrollFools 或 JailFools，把该 dylib 注入目标 App。
   （选 dylib 文件，不要选 deb）
3. 冷启动目标 App，首次进入会强制设置 6 位应用锁密码（两遍确认），
   之后询问是否启用 Face ID / 触控 ID。
4. 设置入口有两个：
   - 锁定界面右上角的齿轮（需先验证密码，只进设置不解锁应用）
   - 应用内双指双击（已解锁状态下直接呼出设置）

常见问题
--------
Q: 注入后没有任何反应？
A: 确认注入的是本 dylib（不是旧版 tweak 版，旧版依赖 CydiaSubstrate，
   在无 substrate 的注入环境里不会加载），并重启一次目标 App。

Q: 没有面容解锁按钮？
A: Face ID 要求宿主 App 的 Info.plist 里有 NSFaceIDUsageDescription。
   QQ 等已声明；未声明的 App 会自动只用密码，不会崩溃。
   想给某个 App 开启：重签 IPA 时在 Info.plist 加
   NSFaceIDUsageDescription = 用于解锁应用。

Q: 忘记密码？
A: 锁屏底部「忘记密码？」→ 验证设备锁屏密码 / 系统面容 →
   锁屏界面内出现「重置应用锁」，确认后清除记录回到首次设置。
   建议设备务必设置锁屏密码，否则重置门槛会降低。

Q: 能不能全局给所有 App 上锁？
A: 本版本不提供。全局方案请用 BioProtect 这类插件。

安全边界
--------
它防的是"随手借用手机的人直接打开某个 App"。
有文件系统权限的进程（Filza 等）可以删掉注入记录或改 App 沙盒偏好，
这一点与所有应用内注入方案相同。

版本
----
基于 tien0246/ProtectedApp 重构，移除了原版「点取消即可绕过面容」
「锁定时快速返回直接解锁」「密码明文存储」「默认密码 0000」等问题。
