/***********************************************************************
 * 应用锁+ (AppLock+) 重构版 v0.2.0
 *
 * 原始项目: https://github.com/tien0246/ProtectedApp (tien0246)
 * 魔改版缺陷(已修复):
 *   1. 面容 ID 弹窗点「取消」即可直接进入应用 (致命漏洞)
 *   2. 密码明文存储在 NSUserDefaults, 且首次默认 0000
 *   3. 设置入口是隐藏手势, 无真正设置面板
 *   4. 锁定状态下快速返回应用可直接解除锁定 (宽限期逻辑缺陷)
 *
 * 重构版特性:
 *   - 面容/触控 ID 验证失败或取消后, 一律停留在密码键盘 (无法绕过)
 *   - 首次启动强制设置 6 位应用锁密码, 不可跳过
 *   - 完整设置面板: 修改密码 / 面容ID开关 / 重新锁定时机
 *   - 密码经 PBKDF2-SHA256 (2万次迭代+随机盐) 哈希, 优先存 Keychain
 *   - 兼容旧版明文密码: 自动读取并转为哈希 (无需重设)
 *   - 错误 5 次起指数冷却 (1,2,4,8...分钟), 状态持久化, 杀进程不重置
 *   - 退后台立即遮盖 (防后台快照泄露), 支持 UIScene/SwiftUI 应用
 *   - 设置入口: 锁屏右上角齿轮 或 应用内双指双击
 *
 * 构建: theos, make package (详见 README.md)
 ***********************************************************************/

#import <UIKit/UIKit.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <objc/runtime.h>
#import <objc/message.h>

#pragma mark - 常量

static NSString * const kPrefPrefix      = @"APL_";
static NSString * const kKeychainService = @"com.applockplus.pin";
static NSString * const kKeychainAccount = @"pinrecord";
static NSString * const kTweakVersion    = @"0.4.2";
static NSInteger       kPinLengthNew     = 6;   // 新设置的密码固定 6 位
static NSInteger       kMaxAttempts      = 5;   // 连错 5 次开始冷却

static NSString *APLPref(NSString *key) { return [kPrefPrefix stringByAppendingString:key]; }

#pragma mark - 工具函数

static NSData *ALRandomData(NSUInteger length) {
    NSMutableData *d = [NSMutableData dataWithLength:length];
    if (SecRandomCopyBytes(kSecRandomDefault, length, d.mutableBytes) != errSecSuccess) return nil;
    return d;
}

/* 输出格式: pbkdf2-sha256$rounds$saltB64$hashB64 */
static NSString *ALHashPIN(NSString *pin, NSData *salt, NSUInteger rounds) {
    const char *pw = pin.UTF8String;
    if (!pw) return nil;
    NSMutableData *dk = [NSMutableData dataWithLength:32];
    int r = CCKeyDerivationPBKDF(kCCPBKDF2, pw, strlen(pw),
                                 salt.bytes, salt.length,
                                 kCCPRFHmacAlgSHA256, (unsigned)rounds,
                                 dk.mutableBytes, dk.length);
    if (r != kCCSuccess) return nil;
    return [NSString stringWithFormat:@"pbkdf2-sha256$%lu$%@$%@",
            (unsigned long)rounds,
            [salt base64EncodedStringWithOptions:0],
            [dk base64EncodedStringWithOptions:0]];
}

static BOOL ALConstTimeEqual(NSData *a, NSData *b) {
    if (a.length != b.length) return NO;
    const uint8_t *x = a.bytes, *y = b.bytes;
    volatile uint8_t diff = 0;
    for (NSUInteger i = 0; i < a.length; i++) diff |= x[i] ^ y[i];
    return diff == 0;
}

static NSString *ALHumanizeInterval(NSTimeInterval iv) {
    long s = (long)ceil(iv);
    if (s < 0) s = 0;
    if (s < 60) return [NSString stringWithFormat:@"%ld 秒", s];
    long m = s / 60, rm = s % 60;
    if (m < 60) return rm ? [NSString stringWithFormat:@"%ld 分 %ld 秒", m, rm]
                          : [NSString stringWithFormat:@"%ld 分钟", m];
    long h = m / 60; m %= 60;
    if (h < 24) return [NSString stringWithFormat:@"%ld 小时 %ld 分", h, m];
    long d = h / 24; h %= 24;
    return [NSString stringWithFormat:@"%ld 天 %ld 小时", d, h];
}

#pragma mark - ALStore (密码哈希与偏好存储)

@interface ALStore : NSObject
@property (nonatomic, assign) NSTimeInterval graceInterval;  // 离开多少秒后重新锁定
@property (nonatomic, assign) NSTimeInterval autoBioDelay;   // 自动面容验证延迟: -1 关闭, 0 立即, >0 秒数
@property (nonatomic, assign) BOOL gestureEnabled;           // 应用内双指双击呼出设置
@property (nonatomic, assign) BOOL biometricEnabled;
@property (nonatomic, assign) NSInteger pinLength;           // 4 或 6
@property (nonatomic, assign) NSInteger failedAttempts;
@property (nonatomic, strong) NSDate *lockoutEnd;
@property (nonatomic, readonly) BOOL hasPIN;
@property (nonatomic, readonly) BOOL isLockedOut;
+ (instancetype)shared;
- (BOOL)setPIN:(NSString *)pin;
- (BOOL)verifyPIN:(NSString *)pin;
- (void)clearLockState;
- (void)resetAll;   // 忘记密码: 清除 Keychain 记录与全部偏好, 回到首次设置状态
- (void)migrateFromLegacy;
@end

@implementation ALStore {
    NSString *_pinRecord;   // pbkdf2 记录串
    BOOL _pinInKeychain;
}

+ (instancetype)shared {
    static ALStore *s = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ s = [[ALStore alloc] init]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        // 注意: 0 是合法值("立即锁定"), 不能用 doubleForKey 的 0 来判断未设置
        _graceInterval = [d objectForKey:APLPref(@"GraceInterval")]
                       ? [d doubleForKey:APLPref(@"GraceInterval")]
                       : 15.0; // 首次安装默认 15 秒
        if (_graceInterval < 0) _graceInterval = 15.0;
        _autoBioDelay = [d objectForKey:APLPref(@"AutoBioDelay")]
                      ? [d doubleForKey:APLPref(@"AutoBioDelay")]
                      : 2.0; // 默认延迟 2 秒, 给用户点齿轮/输密码的时间
        if (_autoBioDelay < -1) _autoBioDelay = 2.0;
        _gestureEnabled = [d objectForKey:APLPref(@"GestureEnabled")]
                        ? [d boolForKey:APLPref(@"GestureEnabled")]
                        : YES; // 默认开启
        _biometricEnabled = [d boolForKey:APLPref(@"BiometricEnabled")];
        _pinLength = [d integerForKey:APLPref(@"PinLength")];
        if (_pinLength != 4 && _pinLength != 6) _pinLength = kPinLengthNew;
        _failedAttempts = [d integerForKey:APLPref(@"FailedAttempts")];
        double end = [d doubleForKey:APLPref(@"LockoutEnd")];
        _lockoutEnd = (end > 0) ? [[NSDate alloc] initWithTimeIntervalSince1970:end] : nil;

        _pinRecord = [self keychainGet];
        _pinInKeychain = (_pinRecord != nil);
        if (!_pinRecord) _pinRecord = [d stringForKey:APLPref(@"PinRecordFallback")];

        [self migrateFromLegacy];
    }
    return self;
}

- (void)setGraceInterval:(NSTimeInterval)v {
    _graceInterval = v;
    [[NSUserDefaults standardUserDefaults] setDouble:v forKey:APLPref(@"GraceInterval")];
}
- (void)setAutoBioDelay:(NSTimeInterval)v {
    _autoBioDelay = v;
    [[NSUserDefaults standardUserDefaults] setDouble:v forKey:APLPref(@"AutoBioDelay")];
}
- (void)setGestureEnabled:(BOOL)v {
    _gestureEnabled = v;
    [[NSUserDefaults standardUserDefaults] setBool:v forKey:APLPref(@"GestureEnabled")];
}
- (void)setBiometricEnabled:(BOOL)v {
    _biometricEnabled = v;
    [[NSUserDefaults standardUserDefaults] setBool:v forKey:APLPref(@"BiometricEnabled")];
}
- (void)setPinLength:(NSInteger)v {
    _pinLength = v;
    [[NSUserDefaults standardUserDefaults] setInteger:v forKey:APLPref(@"PinLength")];
}
- (void)setFailedAttempts:(NSInteger)v {
    _failedAttempts = v;
    [[NSUserDefaults standardUserDefaults] setInteger:v forKey:APLPref(@"FailedAttempts")];
}
- (void)setLockoutEnd:(NSDate *)v {
    _lockoutEnd = v;
    [[NSUserDefaults standardUserDefaults] setDouble:(v ? [v timeIntervalSince1970] : 0)
                                             forKey:APLPref(@"LockoutEnd")];
}

- (BOOL)hasPIN { return _pinRecord.length > 0; }

- (BOOL)isLockedOut {
    return _lockoutEnd && [[NSDate date] compare:_lockoutEnd] == NSOrderedAscending;
}

- (void)clearLockState {
    self.failedAttempts = 0;
    self.lockoutEnd = nil;
}

/* 忘记密码时的一键初始化:
 * 密码哈希存在宿主 App 的 Keychain (App 删除/重装都会保留) 与沙盒偏好里,
 * 卸载或重注入 dylib 都不会清除, 必须在这里显式删除。 */
- (void)resetAll {
    // 1) 删除 Keychain 记录
    NSDictionary *q = @{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
                        (__bridge id)kSecAttrService:kKeychainService,
                        (__bridge id)kSecAttrAccount:kKeychainAccount};
    SecItemDelete((__bridge CFDictionaryRef)q);
    _pinRecord = nil;
    _pinInKeychain = NO;

    // 2) 清除沙盒偏好 (应用锁全部键 + 可能残留的旧版键)
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSArray *keys = @[
        APLPref(@"GraceInterval"), APLPref(@"BiometricEnabled"),
        APLPref(@"AutoBioDelay"),   APLPref(@"PinLength"),
        APLPref(@"FailedAttempts"), APLPref(@"LockoutEnd"),
        APLPref(@"PinRecordFallback"), APLPref(@"GestureEnabled"),
        @"com.tien0246.ProtectedApp", @"timeoutInterval",
    ];
    for (NSString *k in keys) [d removeObjectForKey:k];
    [d synchronize];

    // 3) 内存状态回到默认
    _graceInterval    = 15.0;
    _autoBioDelay     = 2.0;
    _gestureEnabled   = YES;
    _biometricEnabled = NO;
    _pinLength        = kPinLengthNew;
    _failedAttempts   = 0;
    _lockoutEnd       = nil;
}

/* ---------- Keychain ---------- */

- (NSString *)keychainGet {
    NSDictionary *q = @{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
                        (__bridge id)kSecAttrService:kKeychainService,
                        (__bridge id)kSecAttrAccount:kKeychainAccount,
                        (__bridge id)kSecReturnData:@YES,
                        (__bridge id)kSecMatchLimit:(__bridge id)kSecMatchLimitOne};
    CFTypeRef out = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
    if (st != errSecSuccess || !out) return nil;
    NSData *data = CFBridgingRelease(out);
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

- (BOOL)keychainSet:(NSString *)value {
    NSDictionary *q = @{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
                        (__bridge id)kSecAttrService:kKeychainService,
                        (__bridge id)kSecAttrAccount:kKeychainAccount};
    SecItemDelete((__bridge CFDictionaryRef)q);
    NSMutableDictionary *add = [q mutableCopy];
    add[(__bridge id)kSecValueData]      = [value dataUsingEncoding:NSUTF8StringEncoding];
    add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    return SecItemAdd((__bridge CFDictionaryRef)add, NULL) == errSecSuccess;
}

/* ---------- 密码 ---------- */

- (BOOL)setPIN:(NSString *)pin {
    if (pin.length != 4 && pin.length != 6) return NO;
    NSString *record = ALHashPIN(pin, ALRandomData(16), 20000);
    if (!record) return NO;

    BOOL ok = [self keychainSet:record];
    if (ok) {
        _pinInKeychain = YES;
        [[NSUserDefaults standardUserDefaults] removeObjectForKey:APLPref(@"PinRecordFallback")];
    } else {
        // Keychain 不可用时退回 NSUserDefaults (仍为哈希, 不存明文)
        _pinInKeychain = NO;
        [[NSUserDefaults standardUserDefaults] setObject:record forKey:APLPref(@"PinRecordFallback")];
    }
    _pinRecord = record;
    self.pinLength = pin.length;
    return YES;
}

- (BOOL)verifyPIN:(NSString *)pin {
    NSArray *parts = [_pinRecord componentsSeparatedByString:@"$"];
    if (parts.count != 4 || ![parts[0] isEqualToString:@"pbkdf2-sha256"]) return NO;
    NSUInteger rounds = (NSUInteger)[parts[1] integerValue];
    NSData *salt   = [[NSData alloc] initWithBase64EncodedString:parts[2] options:0];
    NSData *expect = [[NSData alloc] initWithBase64EncodedString:parts[3] options:0];
    if (!salt || !expect || rounds == 0 || rounds > 1000000) return NO;

    const char *pw = pin.UTF8String;
    if (!pw) return NO;
    uint8_t dk[32];
    int r = CCKeyDerivationPBKDF(kCCPBKDF2, pw, strlen(pw), salt.bytes, salt.length,
                                 kCCPRFHmacAlgSHA256, (unsigned)rounds, dk, sizeof(dk));
    if (r != kCCSuccess) return NO;
    NSData *got = [NSData dataWithBytes:dk length:sizeof(dk)];
    return ALConstTimeEqual(got, expect);
}

/* ---------- 旧版迁移 ---------- */

- (void)migrateFromLegacy {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    // 旧魔改版/原版: 明文密码存于 com.tien0246.ProtectedApp → passcode
    NSDictionary *legacy = [d objectForKey:@"com.tien0246.ProtectedApp"];
    NSString *legacyPin = legacy[@"passcode"];
    if (!self.hasPIN && [legacyPin isKindOfClass:[NSString class]] &&
        (legacyPin.length == 4 || legacyPin.length == 6)) {
        [self setPIN:legacyPin];
    }
    if (legacy) [d removeObjectForKey:@"com.tien0246.ProtectedApp"];
    // 旧版超时键
    double legacyTimeout = [d doubleForKey:@"timeoutInterval"];
    if (legacyTimeout > 0 && [d objectForKey:APLPref(@"GraceInterval")] == nil) {
        self.graceInterval = legacyTimeout;
    }
    [d removeObjectForKey:@"timeoutInterval"];
}

@end

#pragma mark - 生物识别辅助

static BOOL ALBiometricsAvailable(LABiometryType *outType) {
    LAContext *ctx = [[LAContext alloc] init];
    NSError *err = nil;
    if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&err]) return NO;
    LABiometryType t = ctx.biometryType;
    // Face ID 需要宿主 App 声明 NSFaceIDUsageDescription, 否则调用会直接崩溃, 此处禁用
    if ((t == LABiometryTypeFaceID || t == (LABiometryType)4 /* OpticalID, visionOS */) &&
        ![[NSBundle mainBundle] objectForInfoDictionaryKey:@"NSFaceIDUsageDescription"]) {
        return NO;
    }
    if (outType) *outType = t;
    return YES;
}

#pragma mark - 前置类声明

@class ALLockViewController;
@class ALSettingsController;

@interface ALManager : NSObject
@property (nonatomic, strong) UIWindow *lockWindow;
@property (nonatomic, strong) ALLockViewController *lockVC;
@property (nonatomic, assign, getter=isLocked) BOOL locked;
@property (nonatomic, strong) NSDate *lastResignDate;
@property (nonatomic, strong) NSMutableArray<UITapGestureRecognizer *> *inAppTaps; // 双指双击手势 (每个 window 一个)
+ (instancetype)shared;
- (void)bootstrapIfNeeded;
- (void)unlockSucceeded;
- (void)attachInAppGesture; // 供设置面板手势开关即时生效调用
@end

typedef NS_ENUM(NSInteger, ALVerifyPurpose) {
    ALVerifyUnlock,       // 正常解锁
    ALVerifyForSettings,  // 仅为了进入设置 (不解锁应用)
    ALVerifyChangePIN,    // 修改密码三步流程 (当前密码 → 新密码 → 确认)
};

@interface ALLockViewController : UIViewController
@property (nonatomic, assign, getter=isSetupMode) BOOL setupMode;
@property (nonatomic, assign) ALVerifyPurpose purpose;
@property (nonatomic, assign) NSInteger setupStep;
@property (nonatomic, copy) NSString *pendingPIN;
@property (nonatomic, strong) NSMutableString *entered;
@property (nonatomic, strong) UIImageView *iconView;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UILabel *countdownLabel;
@property (nonatomic, strong) UIStackView *dotsStack;
@property (nonatomic, strong) NSMutableArray<UIView *> *dots;
@property (nonatomic, strong) UIStackView *padStack;
@property (nonatomic, strong) UIStackView *resetStack;     // 锁屏内重置确认 (替代系统弹窗, 无展示竞态)
@property (nonatomic, assign) BOOL confirmResetMode;
@property (nonatomic, strong) UIButton *faceIDButton;
@property (nonatomic, strong) UIButton *deleteButton;
@property (nonatomic, strong) UIButton *gearButton;
@property (nonatomic, strong) UIButton *forgotButton;
@property (nonatomic, strong) NSTimer *countdownTimer;
@property (nonatomic, strong) LAContext *currentContext;
@property (nonatomic, strong) UINotificationFeedbackGenerator *haptic;
@property (nonatomic, assign) BOOL biometricInFlight;
@property (nonatomic, assign) BOOL padVisible;
@property (nonatomic, assign) BOOL autoBioDone;
@property (nonatomic, assign) NSInteger autoBioGeneration; // 用于取消已调度的延迟自动面容
@property (nonatomic, assign) BOOL ownerAuthActive;        // 设备所有者验证进行中, 期间禁止自动面容
- (void)prepareCover;
- (void)showLockUI;
- (void)showResetConfirm;
- (void)confirmResetPressed;
- (void)cancelResetPressed;
- (void)digitPressed:(UIButton *)sender;
- (void)deletePressed;
- (void)faceIDPressed;
- (void)gearPressed;
- (void)forgotPressed;
@end

@interface ALSettingsController : UITableViewController
- (instancetype)initWithStyle:(UITableViewStyle)style;
- (void)donePressed;
- (void)bioSwitchChanged:(UISwitch *)sw;
- (void)showChangePINFlow;
- (void)showAutoBioDelaySheet;
- (void)showAlert:(NSString *)title msg:(NSString *)msg;
@end

#pragma mark - ALLockViewController (锁定界面)

@implementation ALLockViewController

- (NSInteger)requiredLength {
    if (self.isSetupMode) return kPinLengthNew;
    if (self.purpose == ALVerifyChangePIN) {
        if (self.setupStep == 0) { // 当前密码长度与既有密码一致
            NSInteger l = [ALStore shared].pinLength;
            return (l == 4 || l == 6) ? l : kPinLengthNew;
        }
        return kPinLengthNew;      // 新密码固定 6 位
    }
    NSInteger l = [ALStore shared].pinLength;
    return (l == 4 || l == 6) ? l : kPinLengthNew;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.entered = [NSMutableString string];
    self.dots = [NSMutableArray array];
    self.haptic = [[UINotificationFeedbackGenerator alloc] init];
    [self buildUI];
    // 直接以模态方式呈现(修改密码流程)时的初始状态;
    // 锁屏流程由 showLockUI / prepareCover 驱动, 不受影响
    if (self.purpose == ALVerifyChangePIN) {
        self.padVisible = YES;
        self.gearButton.hidden = YES;
        self.faceIDButton.hidden = YES;
        self.forgotButton.hidden = YES; // 改密流程没有"忘记"入口 (能进改密说明记得当前密码)
        [self refreshDots];
        [self updateHeader];
    }
}

- (void)buildUI {
    UIView *root = self.view;
    root.backgroundColor = [UIColor colorWithWhite:0.08 alpha:1.0];

    UIVisualEffectView *blur = [[UIVisualEffectView alloc]
        initWithEffect:[UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemUltraThinMaterialDark]];
    blur.translatesAutoresizingMaskIntoConstraints = NO;
    [root addSubview:blur];
    [NSLayoutConstraint activateConstraints:@[
        [blur.leadingAnchor constraintEqualToAnchor:root.leadingAnchor],
        [blur.trailingAnchor constraintEqualToAnchor:root.trailingAnchor],
        [blur.topAnchor constraintEqualToAnchor:root.topAnchor],
        [blur.bottomAnchor constraintEqualToAnchor:root.bottomAnchor],
    ]];

    self.iconView = [[UIImageView alloc] initWithImage:[UIImage systemImageNamed:@"lock.fill"]];
    self.iconView.tintColor = [UIColor whiteColor];
    self.iconView.contentMode = UIViewContentModeScaleAspectFit;
    self.iconView.translatesAutoresizingMaskIntoConstraints = NO;

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.textColor = [UIColor whiteColor];
    self.statusLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightMedium];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 2;
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;

    self.countdownLabel = [[UILabel alloc] init];
    self.countdownLabel.textColor = [UIColor colorWithRed:1.0 green:0.45 blue:0.42 alpha:1.0];
    self.countdownLabel.font = [UIFont systemFontOfSize:13];
    self.countdownLabel.textAlignment = NSTextAlignmentCenter;
    self.countdownLabel.numberOfLines = 2;
    self.countdownLabel.translatesAutoresizingMaskIntoConstraints = NO;

    self.dotsStack = [[UIStackView alloc] init];
    self.dotsStack.axis = UILayoutConstraintAxisHorizontal;
    self.dotsStack.spacing = 14;
    self.dotsStack.alignment = UIStackViewAlignmentCenter;
    self.dotsStack.translatesAutoresizingMaskIntoConstraints = NO;

    self.padStack = [[UIStackView alloc] init];
    self.padStack.axis = UILayoutConstraintAxisVertical;
    self.padStack.spacing = 16;
    self.padStack.alignment = UIStackViewAlignmentCenter;
    self.padStack.translatesAutoresizingMaskIntoConstraints = NO;
    [self buildPad];

    self.gearButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.gearButton.tintColor = [UIColor colorWithWhite:1 alpha:0.7];
    [self.gearButton setImage:[UIImage systemImageNamed:@"gearshape.fill"] forState:UIControlStateNormal];
    self.gearButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.gearButton addTarget:self action:@selector(gearPressed)
              forControlEvents:UIControlEventTouchUpInside];

    self.forgotButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.forgotButton setTitle:@"忘记密码？" forState:UIControlStateNormal];
    self.forgotButton.titleLabel.font = [UIFont systemFontOfSize:15];
    self.forgotButton.tintColor = [UIColor colorWithWhite:1 alpha:0.55];
    self.forgotButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.forgotButton addTarget:self action:@selector(forgotPressed)
              forControlEvents:UIControlEventTouchUpInside];

    UIButton *resetBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [resetBtn setTitle:@"重置应用锁" forState:UIControlStateNormal];
    resetBtn.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    [resetBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    resetBtn.backgroundColor = [UIColor systemRedColor];
    resetBtn.layer.cornerRadius = 12;
    resetBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [resetBtn addTarget:self action:@selector(confirmResetPressed)
       forControlEvents:UIControlEventTouchUpInside];

    UIButton *cancelBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [cancelBtn setTitle:@"取消" forState:UIControlStateNormal];
    cancelBtn.titleLabel.font = [UIFont systemFontOfSize:17];
    cancelBtn.tintColor = [UIColor colorWithWhite:1 alpha:0.75];
    cancelBtn.backgroundColor = [UIColor colorWithWhite:1.0 alpha:0.14];
    cancelBtn.layer.cornerRadius = 12;
    cancelBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [cancelBtn addTarget:self action:@selector(cancelResetPressed)
       forControlEvents:UIControlEventTouchUpInside];

    self.resetStack = [[UIStackView alloc] initWithArrangedSubviews:@[resetBtn, cancelBtn]];
    self.resetStack.axis = UILayoutConstraintAxisVertical;
    self.resetStack.spacing = 12;
    self.resetStack.alignment = UIStackViewAlignmentCenter;
    self.resetStack.translatesAutoresizingMaskIntoConstraints = NO;
    self.resetStack.hidden = YES;
    [resetBtn.widthAnchor constraintEqualToConstant:220].active = YES;
    [resetBtn.heightAnchor constraintEqualToConstant:46].active = YES;
    [cancelBtn.widthAnchor constraintEqualToConstant:220].active = YES;
    [cancelBtn.heightAnchor constraintEqualToConstant:44].active = YES;

    UIStackView *main = [[UIStackView alloc] initWithArrangedSubviews:@[
        self.iconView, self.statusLabel, self.dotsStack, self.countdownLabel,
        self.resetStack, self.padStack
    ]];
    main.axis = UILayoutConstraintAxisVertical;
    main.alignment = UIStackViewAlignmentCenter;
    main.spacing = 20;
    main.translatesAutoresizingMaskIntoConstraints = NO;

    [root addSubview:main];
    [root addSubview:self.gearButton];
    [root addSubview:self.forgotButton];
    [NSLayoutConstraint activateConstraints:@[
        [main.centerXAnchor constraintEqualToAnchor:root.centerXAnchor],
        [main.centerYAnchor constraintEqualToAnchor:root.centerYAnchor constant:-24],
        [main.leadingAnchor constraintGreaterThanOrEqualToAnchor:root.leadingAnchor constant:16],
        [main.trailingAnchor constraintLessThanOrEqualToAnchor:root.trailingAnchor constant:-16],
        [self.iconView.widthAnchor constraintEqualToConstant:34],
        [self.iconView.heightAnchor constraintEqualToConstant:34],
        [self.statusLabel.widthAnchor constraintLessThanOrEqualToConstant:280],
        [self.countdownLabel.widthAnchor constraintLessThanOrEqualToConstant:280],
        [self.gearButton.topAnchor constraintEqualToAnchor:root.safeAreaLayoutGuide.topAnchor constant:14],
        [self.gearButton.trailingAnchor constraintEqualToAnchor:root.safeAreaLayoutGuide.trailingAnchor constant:-18],
        [self.gearButton.widthAnchor constraintEqualToConstant:40],
        [self.gearButton.heightAnchor constraintEqualToConstant:40],
        [self.forgotButton.centerXAnchor constraintEqualToAnchor:root.centerXAnchor],
        [self.forgotButton.bottomAnchor constraintEqualToAnchor:root.safeAreaLayoutGuide.bottomAnchor constant:-16],
    ]];
}

- (UIButton *)padButtonWithTitle:(NSString *)title {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    [b setTitle:title forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont systemFontOfSize:26];
    [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    b.backgroundColor = [UIColor colorWithWhite:1.0 alpha:0.14];
    b.layer.cornerRadius = 34;
    b.translatesAutoresizingMaskIntoConstraints = NO;
    [b.widthAnchor constraintEqualToConstant:68].active = YES;
    [b.heightAnchor constraintEqualToConstant:68].active = YES;
    [b addTarget:self action:@selector(digitPressed:) forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (UIButton *)padButtonWithImage:(NSString *)imageName sel:(SEL)sel {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.tintColor = [UIColor whiteColor];
    [b setImage:[UIImage systemImageNamed:imageName] forState:UIControlStateNormal];
    b.backgroundColor = [UIColor colorWithWhite:1.0 alpha:0.14];
    b.layer.cornerRadius = 34;
    b.translatesAutoresizingMaskIntoConstraints = NO;
    [b.widthAnchor constraintEqualToConstant:68].active = YES;
    [b.heightAnchor constraintEqualToConstant:68].active = YES;
    [b addTarget:self action:sel forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (void)buildPad {
    self.faceIDButton = [self padButtonWithImage:@"faceid" sel:@selector(faceIDPressed)];
    self.deleteButton = [self padButtonWithImage:@"delete.left" sel:@selector(deletePressed)];

    NSArray *rowDefs = @[@[@"1", @"2", @"3"],
                         @[@"4", @"5", @"6"],
                         @[@"7", @"8", @"9"]];
    for (NSArray *row in rowDefs) {
        UIStackView *h = [[UIStackView alloc] initWithArrangedSubviews:@[
            [self padButtonWithTitle:row[0]],
            [self padButtonWithTitle:row[1]],
            [self padButtonWithTitle:row[2]],
        ]];
        h.axis = UILayoutConstraintAxisHorizontal;
        h.spacing = 20;
        [self.padStack addArrangedSubview:h];
    }

    UIStackView *lastRow = [[UIStackView alloc] initWithArrangedSubviews:@[
        self.faceIDButton,
        [self padButtonWithTitle:@"0"],
        self.deleteButton,
    ]];
    lastRow.axis = UILayoutConstraintAxisHorizontal;
    lastRow.spacing = 20;
    [self.padStack addArrangedSubview:lastRow];
}

#pragma mark 状态刷新

- (void)showLockUI {
    [self view]; // 确保视图已加载
    BOOL wasHidden = !self.padVisible;
    self.padVisible = YES;
    self.setupMode = ([ALStore shared].hasPIN == NO);

    // 从纯遮盖模式恢复显示锁定 UI
    self.iconView.hidden = NO;
    self.dotsStack.hidden = NO;
    self.padStack.hidden = NO;
    self.gearButton.hidden = self.isSetupMode;
    self.forgotButton.hidden = self.isSetupMode;

    if (wasHidden) {
        // 只在重新上锁时重置输入状态; 通知中心来回拉不会打断正在输入的密码
        self.purpose = ALVerifyUnlock;
        self.setupStep = 0;
        self.pendingPIN = nil;
        self.autoBioDone = NO;
        self.ownerAuthActive = NO; // 遮盖→锁定界面的转换意味着重置流程已被打断
        [self.entered setString:@""];
        [self refreshDots];
        [self updateHeader];
    }
    [self refreshLockoutUI];
    [self refreshBiometricButton];
    [self maybeAutoBiometrics];
}

- (void)prepareCover {
    [self view];
    self.padVisible = NO;
    [self cancelAutoBiometrics]; // 遮盖模式下不应有待触发的面容
    // 纯遮盖模式: 只留模糊背景, 防止 App 切换器缩略图泄露界面与密码盘
    self.iconView.hidden = YES;
    self.dotsStack.hidden = YES;
    self.padStack.hidden = YES;
    self.gearButton.hidden = YES;
    self.forgotButton.hidden = YES;
    [self.entered setString:@""];
    [self refreshDots];
    self.statusLabel.text = @"";
    self.countdownLabel.text = @"";
    [self stopCountdownTimer];
}

- (void)updateHeader {
    if (self.isSetupMode) {
        self.iconView.image = [UIImage systemImageNamed:@"lock.badge"];
        self.statusLabel.text = (self.setupStep == 0)
            ? @"首次使用：请设置 6 位应用锁密码"
            : @"请再次输入以确认密码";
    } else if (self.purpose == ALVerifyChangePIN) {
        self.iconView.image = [UIImage systemImageNamed:@"lock.rotation"];
        self.statusLabel.text = (self.setupStep == 0) ? @"请输入当前应用锁密码"
            : (self.setupStep == 1) ? @"请输入新的 6 位密码"
            : @"请再次输入新密码";
    } else {
        self.iconView.image = [UIImage systemImageNamed:@"lock.fill"];
        self.statusLabel.text = (self.purpose == ALVerifyForSettings)
            ? @"输入密码以进入设置"
            : @"应用已锁定，请输入密码";
    }
}

- (void)refreshDots {
    NSInteger n = self.requiredLength;
    if (self.dots.count != (NSUInteger)n) {
        for (UIView *v in self.dots) [v removeFromSuperview];
        [self.dots removeAllObjects];
        [self.dotsStack.arrangedSubviews makeObjectsPerformSelector:@selector(removeFromSuperview)];
        for (NSInteger i = 0; i < n; i++) {
            UIView *dot = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 15, 15)];
            dot.layer.cornerRadius = 7.5;
            dot.layer.borderWidth = 1.2;
            dot.layer.borderColor = [[UIColor colorWithWhite:1 alpha:0.85] CGColor];
            dot.backgroundColor = [UIColor clearColor];
            dot.translatesAutoresizingMaskIntoConstraints = NO;
            [dot.widthAnchor constraintEqualToConstant:15].active = YES;
            [dot.heightAnchor constraintEqualToConstant:15].active = YES;
            [self.dotsStack addArrangedSubview:dot];
            [self.dots addObject:dot];
        }
    }
    for (NSInteger i = 0; i < n; i++) {
        UIView *dot = self.dots[i];
        BOOL filled = (i < (NSInteger)self.entered.length);
        dot.backgroundColor = filled ? [UIColor whiteColor] : [UIColor clearColor];
    }
}

- (void)refreshBiometricButton {
    LABiometryType t;
    BOOL available = ALBiometricsAvailable(&t);
    BOOL enabled = [ALStore shared].biometricEnabled && available;
    NSString *symbol = (t == LABiometryTypeTouchID) ? @"touchid" : @"faceid";
    [self.faceIDButton setImage:[UIImage systemImageNamed:symbol] forState:UIControlStateNormal];
    BOOL interactive = enabled && ![ALStore shared].isLockedOut;
    self.faceIDButton.enabled = interactive;
    self.faceIDButton.alpha = enabled ? 1.0 : 0.25;
}

- (void)refreshLockoutUI {
    BOOL out = [ALStore shared].isLockedOut;
    self.padStack.userInteractionEnabled = !out;
    self.padStack.alpha = out ? 0.35 : 1.0;
    if (out) {
        [self tickCountdown];
        [self startCountdownTimer];
    } else {
        self.countdownLabel.text = @"";
        [self stopCountdownTimer];
    }
    [self refreshBiometricButton];
}

#pragma mark 冷却倒计时

- (void)startCountdownTimer {
    if ([self.countdownTimer isValid]) return;
    self.countdownTimer = [NSTimer scheduledTimerWithTimeInterval:1.0
                                                           target:self
                                                         selector:@selector(tickCountdown)
                                                         userInfo:nil
                                                          repeats:YES];
}

- (void)stopCountdownTimer {
    [self.countdownTimer invalidate];
    self.countdownTimer = nil;
}

- (void)tickCountdown {
    NSDate *end = [ALStore shared].lockoutEnd;
    NSTimeInterval left = end ? [end timeIntervalSinceNow] : 0;
    if (left <= 0) {
        [ALStore shared].lockoutEnd = nil;
        [ALStore shared].failedAttempts = 0;
        [self refreshLockoutUI];
        self.statusLabel.text = @"请输入密码";
        [self maybeAutoBiometrics];
        return;
    }
    self.countdownLabel.text = [NSString stringWithFormat:@"错误次数过多，%@ 后可重试",
                                ALHumanizeInterval(left)];
}

#pragma mark 输入

- (void)digitPressed:(UIButton *)sender {
    [self cancelAutoBiometrics]; // 用户开始输密码: 取消待触发的自动面容
    if ([ALStore shared].isLockedOut) return;
    if (!self.padVisible) return;
    if ((NSInteger)self.entered.length >= self.requiredLength) return;
    [self.entered appendString:sender.currentTitle];
    [self refreshDots];
    if ((NSInteger)self.entered.length == self.requiredLength) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.12 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self submitEnteredCode]; });
    }
}

- (void)deletePressed {
    if (self.entered.length > 0) {
        [self.entered deleteCharactersInRange:NSMakeRange(self.entered.length - 1, 1)];
        [self refreshDots];
    }
}

- (void)submitEnteredCode {
    NSString *code = [self.entered copy];
    ALStore *st = [ALStore shared];

    if (self.isSetupMode) {
        if (self.setupStep == 0) {
            self.pendingPIN = [code copy];
            self.setupStep = 1;
            [self.entered setString:@""];
            [self refreshDots];
            [self updateHeader];
        } else {
            if ([code isEqualToString:self.pendingPIN]) {
                if (![st setPIN:code]) {
                    self.setupStep = 0;
                    [self.entered setString:@""];
                    [self refreshDots];
                    [self updateHeader];
                    [self flashStatus:@"密码保存失败，请重试" error:YES];
                    return;
                }
                [self finishSetup];
            } else {
                self.setupStep = 0;
                self.pendingPIN = nil;
                [self.entered setString:@""];
                [self refreshDots];
                [self updateHeader];
                [self flashStatus:@"两次输入不一致，请重新设置" error:YES];
            }
        }
        return;
    }

    if (self.purpose == ALVerifyChangePIN) {
        // 修改密码三步: 当前密码 → 新密码 → 确认新密码
        if (self.setupStep == 0) {
            if (![st verifyPIN:code]) {
                [self handleWrongPIN]; // 错误同样计入冷却计数
                return;
            }
            self.setupStep = 1;
            self.pendingPIN = nil;
            [self.entered setString:@""];
            [self refreshDots];
            [self updateHeader];
        } else if (self.setupStep == 1) {
            self.pendingPIN = [code copy];
            self.setupStep = 2;
            [self.entered setString:@""];
            [self refreshDots];
            [self updateHeader];
        } else {
            if (![code isEqualToString:self.pendingPIN]) {
                self.setupStep = 1;
                self.pendingPIN = nil;
                [self.entered setString:@""];
                [self refreshDots];
                [self updateHeader];
                [self flashStatus:@"两次输入不一致，请重新输入新密码" error:YES];
                return;
            }
            if (![st setPIN:code]) {
                self.setupStep = 1;
                self.pendingPIN = nil;
                [self.entered setString:@""];
                [self refreshDots];
                [self updateHeader];
                [self flashStatus:@"密码保存失败，请重试" error:YES];
                return;
            }
            [self flashStatus:@"应用锁密码已修改" error:NO];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [self dismissViewControllerAnimated:YES completion:nil];
            });
        }
        return;
    }

    if ([st verifyPIN:code]) {
        [self handleAuthSuccess];
    } else {
        [self handleWrongPIN];
    }
}

- (void)handleAuthSuccess {
    if (self.purpose == ALVerifyForSettings) {
        // 只进设置, 不解锁应用
        self.purpose = ALVerifyUnlock;
        [self.entered setString:@""];
        [self refreshDots];
        [self updateHeader];
        [self presentSettings];
    } else {
        [[ALManager shared] unlockSucceeded];
    }
}

- (void)handleWrongPIN {
    ALStore *st = [ALStore shared];
    st.failedAttempts += 1;
    if (st.failedAttempts >= kMaxAttempts) {
        NSInteger exp = st.failedAttempts - kMaxAttempts;
        if (exp > 10) exp = 10;                       // 冷却上限 2^10 分钟 ≈ 17 小时
        NSInteger minutes = (1 << exp);
        st.lockoutEnd = [NSDate dateWithTimeIntervalSinceNow:(minutes * 60 + 1)];
        [self refreshLockoutUI];
    } else {
        [self.entered setString:@""];
        [self refreshDots];
        self.statusLabel.text = [NSString stringWithFormat:@"密码错误，还可尝试 %d 次",
                                 (int)(kMaxAttempts - st.failedAttempts)];
    }
    [self shakeDots];
    [self.haptic notificationOccurred:UINotificationFeedbackTypeError];
}

- (void)flashStatus:(NSString *)text error:(BOOL)isError {
    self.statusLabel.text = text;
    if (isError) {
        [self shakeDots];
        [self.haptic notificationOccurred:UINotificationFeedbackTypeError];
    }
}

- (void)shakeDots {
    CAKeyframeAnimation *anim = [CAKeyframeAnimation animationWithKeyPath:@"transform.translation.x"];
    anim.values = @[@0, @-10, @10, @-6, @6, @0];
    anim.duration = 0.35;
    [self.dotsStack.layer addAnimation:anim forKey:@"al_shake"];
}

#pragma mark 首次设置完成

- (void)finishSetup {
    LABiometryType t;
    if (ALBiometricsAvailable(&t)) {
        NSString *bioName = (t == LABiometryTypeTouchID) ? @"触控 ID" : @"面容 ID";
        UIAlertController *alert =
            [UIAlertController alertControllerWithTitle:[NSString stringWithFormat:@"启用%@？", bioName]
                                                message:@"之后解锁将优先使用生物识别，\n取消或失败时仍需输入密码。"
                                         preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:[NSString stringWithFormat:@"启用%@", bioName]
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction *action) {
            [ALStore shared].biometricEnabled = YES;
            [[ALManager shared] unlockSucceeded];
        }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"暂不启用"
                                                  style:UIAlertActionStyleCancel
                                                handler:^(UIAlertAction *action) {
            [ALStore shared].biometricEnabled = NO;
            [[ALManager shared] unlockSucceeded];
        }]];
        [self presentViewController:alert animated:YES completion:nil];
    } else {
        [ALStore shared].biometricEnabled = NO;
        [[ALManager shared] unlockSucceeded];
    }
}

#pragma mark 面容 / 触控 ID

- (void)faceIDPressed {
    [self cancelAutoBiometrics]; // 用户主动点击: 撤销尚未触发的延迟自动验证
    if (self.purpose == ALVerifyChangePIN) return; // 改密流程不允许生物识别
    if (![ALStore shared].biometricEnabled) {
        LABiometryType t;
        if (ALBiometricsAvailable(&t)) {
            self.statusLabel.text = @"生物识别未启用，请输入密码或在设置中开启";
        } else {
            self.statusLabel.text = @"当前应用无法使用生物识别，请输入密码";
        }
        return;
    }
    [self attemptBiometrics];
}

/* 延迟自动面容验证:
 * 开启面容后, 锁屏一出现就立即刷脸会把用户"闪进"应用,
 * 既看不到锁屏也没时间点齿轮进设置。
 * 改为: 默认延迟数秒(可在设置中调整), 期间任何手动操作(按数字/点面容/点齿轮)
 * 都会取消本次自动验证。 */
- (void)maybeAutoBiometrics {
    if (self.autoBioDone || self.biometricInFlight) return;
    if (self.ownerAuthActive) return; // 设备所有者验证期间绝不调度应用锁自动面容
    if (!self.padVisible || self.isSetupMode) return;
    if (self.purpose == ALVerifyChangePIN) return;
    if (![ALStore shared].biometricEnabled) return;
    if ([ALStore shared].isLockedOut) return;
    // Face ID 只能在前台激活时评估; 退后台时触发的 showLockUI 不调度
    if ([UIApplication sharedApplication].applicationState != UIApplicationStateActive) return;

    NSTimeInterval delay = [ALStore shared].autoBioDelay;
    if (delay < 0) return;           // 已关闭
    if (delay <= 0) {                // 立即
        [self attemptBiometrics];
        return;
    }
    self.autoBioGeneration += 1;
    NSInteger gen = self.autoBioGeneration;
    self.statusLabel.text = [NSString stringWithFormat:@"%.0f 秒后自动验证面容…",
                             (double)(NSInteger)delay];
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        typeof(self) strongSelf = weakSelf;
        if (!strongSelf) return;
        if (strongSelf.autoBioGeneration != gen) return;      // 已被取消
        if (strongSelf.autoBioDone || strongSelf.biometricInFlight) return;
        if (strongSelf.ownerAuthActive) return;               // 设备所有者验证期间不放行
        if (!strongSelf.padVisible || strongSelf.isSetupMode) return;
        if (strongSelf.purpose == ALVerifyChangePIN) return;
        if (![ALStore shared].biometricEnabled) return;
        if ([ALStore shared].isLockedOut) return;
        if ([UIApplication sharedApplication].applicationState != UIApplicationStateActive) return;
        [strongSelf attemptBiometrics];
    });
}

- (void)cancelAutoBiometrics {
    self.autoBioGeneration += 1;
    if (!self.autoBioDone && !self.biometricInFlight && self.padVisible) {
        [self updateHeader]; // 恢复默认提示文案
    }
}

- (void)attemptBiometrics {
    if (self.biometricInFlight || self.isSetupMode) return;
    if (self.ownerAuthActive) return;
    if ([ALStore shared].isLockedOut) return;
    self.autoBioDone = YES;

    LAContext *ctx = [[LAContext alloc] init];
    ctx.localizedFallbackTitle = @"";   // 隐藏系统"输入密码"回退, 我们有自己的密码盘
    NSError *err = nil;
    if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&err]) {
        self.statusLabel.text = @"生物识别不可用，请输入密码";
        return;
    }

    self.currentContext = ctx;          // 持有引用, 防止评估期间被释放
    self.biometricInFlight = YES;
    self.statusLabel.text = @"正在验证…";

    [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
        localizedReason:@"验证以解锁应用"
                  reply:^(BOOL success, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self.biometricInFlight = NO;
            self.currentContext = nil;
            if (success) {
                [self handleAuthSuccess];
            } else {
                /* ★★★ 核心修复 ★★★
                 * 任何失败/取消都停留在密码盘, 绝不解锁。
                 * (旧魔改版在此处取消后直接放行, 导致点"取消"即可进入应用) */
                NSString *msg;
                switch (error.code) {
                    case LAErrorUserCancel:
                    case LAErrorSystemCancel:
                        msg = @"已取消验证，请输入密码";
                        break;
                    case LAErrorBiometryLockout:
                        msg = @"生物识别已被锁定，请输入密码";
                        break;
                    case LAErrorPasscodeNotSet:
                        msg = @"设备未设置锁屏密码，请输入应用密码";
                        break;
                    case LAErrorAuthenticationFailed:
                        msg = @"识别失败，请重试或输入密码";
                        break;
                    default:
                        msg = @"验证未通过，请输入密码";
                        break;
                }
                self.statusLabel.text = msg;
                [self.haptic notificationOccurred:UINotificationFeedbackTypeError];
            }
        });
    }];
}

#pragma mark 忘记密码 (一键初始化)

/* 密码哈希存于宿主 App 的 Keychain(即使删除重装 App 也会保留) 与沙盒偏好,
 * 卸载/重注入 dylib 不会清除; 忘记密码只能走此入口整体重置。
 *
 * 门槛: 必须通过 LAPolicyDeviceOwnerAuthentication 验证设备所有者身份
 * (设备锁屏密码或系统面容/触控 ID)。借用手机的人不知道设备密码就无法重置,
 * 而忘记应用锁密码的机主本人随时可以验证通过。 */
- (void)forgotPressed {
    [self cancelAutoBiometrics];
    if (self.isSetupMode) return;

    LAContext *ctx = [[LAContext alloc] init];
    NSError *err = nil;
    if ([ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&err]) {
        self.ownerAuthActive = YES; // 验证期间禁止自动面容劫持流程
        self.currentContext = ctx;  // 持有引用防止评估期间被释放
        [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
              localizedReason:@"验证设备所有者身份以重置应用锁"
                        reply:^(BOOL success, NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.currentContext = nil;
                if (success) {
                    /* 直接在锁屏界面内展开重置确认 (不使用系统弹窗):
                     * UIAlertController 在系统验证 UI 收起动画之后呈现存在竞态,
                     * 会静默失败导致卡死; 内嵌 UI 从机制上消灭该问题。 */
                    [self showResetConfirm];
                } else {
                    self.ownerAuthActive = NO;
                    [self flashStatus:@"设备验证未通过，无法重置" error:YES];
                }
            });
        }];
    } else {
        // 设备未设置锁屏密码: 没有可验证的所有者凭据, 直接进入确认 (存在风险, 见 README)
        [self showResetConfirm];
    }
}

/* 重置确认: 直接复用锁屏自身布局, 验证通过后立即切换, 无任何弹窗竞态 */
- (void)showResetConfirm {
    [self stopCountdownTimer];
    self.confirmResetMode = YES;
    self.iconView.hidden    = YES;
    self.dotsStack.hidden   = YES;
    self.padStack.hidden    = YES;
    self.gearButton.hidden  = YES;
    self.forgotButton.hidden = YES;
    self.countdownLabel.text = @"";
    self.resetStack.hidden  = NO;
    self.statusLabel.text   = @"已通过设备所有者验证\n重置将删除应用锁密码与全部设置\n(不影响 QQ 本身的数据)";
    self.statusLabel.numberOfLines = 3;
}

- (void)confirmResetPressed {
    [self performReset];
}

- (void)cancelResetPressed {
    self.confirmResetMode = NO;
    self.ownerAuthActive  = NO;
    self.resetStack.hidden = YES;
    self.statusLabel.numberOfLines = 1;
    [self showLockUI]; // 恢复正常锁屏 (含自动面容重新调度)
    [self updateHeader];
}

- (void)performReset {
    [[ALStore shared] resetAll];
    self.confirmResetMode = NO;
    self.ownerAuthActive  = NO;
    self.resetStack.hidden = YES;
    self.statusLabel.numberOfLines = 1;
    self.setupMode  = YES;   // hasPIN 已为 NO, 回到首次设置流程
    self.purpose    = ALVerifyUnlock;
    self.setupStep  = 0;
    self.pendingPIN = nil;
    self.autoBioDone = NO;
    [self.entered setString:@""];
    [self refreshDots];
    [self updateHeader];
    self.gearButton.hidden   = YES;
    self.forgotButton.hidden = YES;
    self.iconView.hidden    = NO;
    self.dotsStack.hidden   = NO;
    self.padStack.hidden    = NO;
    self.countdownLabel.text = @"";
    [self stopCountdownTimer];
    [self refreshLockoutUI];
    [self refreshBiometricButton];
}

#pragma mark 设置入口 (锁屏齿轮)

- (void)gearPressed {
    if (self.isSetupMode) return;
    if ([ALStore shared].isLockedOut) {
        [self tickCountdown];
        return;
    }
    [self cancelAutoBiometrics]; // 撤销"解锁用途"的待触发面容, 换成"进设置用途"
    self.purpose = ALVerifyForSettings;
    [self.entered setString:@""];
    [self refreshDots];
    [self updateHeader];
    // 不再立即刷脸: 同样走延迟逻辑, 给用户输密码的时间 (延迟期间再点面容按钮可立即验证)
    [self maybeAutoBiometrics];
}

- (void)presentSettings {
    ALSettingsController *settings =
        [[ALSettingsController alloc] initWithStyle:UITableViewStyleInsetGrouped];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:settings];
    nav.modalPresentationStyle = UIModalPresentationPageSheet;
    [self presentViewController:nav animated:YES completion:nil];
}

- (void)dealloc {
    [self.countdownTimer invalidate];
}

@end

#pragma mark - ALSettingsController (设置面板)

@implementation ALSettingsController

- (instancetype)initWithStyle:(UITableViewStyle)style {
    self = [super initWithStyle:style];
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"应用锁+ 设置";
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                      target:self
                                                      action:@selector(donePressed)];
}

- (void)donePressed {
    [self dismissViewControllerAnimated:YES completion:^{
        // 关闭设置面板后直接进入应用 (无论入口是锁屏齿轮还是应用内手势):
        // 齿轮流程此前停留在锁屏键盘页, 需要再输一次密码, 体验割裂
        [[ALManager shared] unlockSucceeded];
    }];
}

- (BOOL)biometricsUsable {
    LABiometryType t;
    return ALBiometricsAvailable(&t);
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return 4; }

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (section == 0) return 3;
    if (section == 1) return 4;
    if (section == 2) return 1;
    return 2;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (section == 0) return @"解锁方式";
    if (section == 1) return @"重新锁定时机";
    if (section == 2) return @"密码";
    return @"关于";
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == 0) {
        if (![self biometricsUsable]) {
            return @"当前应用未声明 Face ID 权限或设备不支持生物识别。\n"
                    "Face ID 需要宿主应用 Info.plist 包含 NSFaceIDUsageDescription。";
        }
        return @"开启后解锁时优先使用面容/触控 ID；取消或验证失败时需输入应用锁密码。\n"
                "自动验证留出的延迟时间内，可先输入密码或点齿轮进设置。\n"
                "双指双击：应用已解锁时，在应用内任意页面用两根手指连续轻点两次，"
                "可直接呼出本设置面板（下方开关可关闭）。";
    }
    if (section == 1) return @"应用退到后台超过该时长后，再次打开需要验证。";
    if (section == 3) return @"基于 tien0246/ProtectedApp 重构，修复取消面容 ID 即可绕过的漏洞。";
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *cellId = @"ALCell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cellId];
    if (!cell) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                             reuseIdentifier:cellId];

    cell.accessoryView = nil;
    cell.accessoryType = UITableViewCellAccessoryNone;
    cell.textLabel.textColor = [UIColor labelColor];
    cell.textLabel.font = [UIFont systemFontOfSize:17];

    if (indexPath.section == 0) {
        if (indexPath.row == 1) {
            // 自动验证时机 (需带右侧明细文字的 cell 样式)
            static NSString *valueCellId = @"ALValueCell";
            UITableViewCell *vc = [tableView dequeueReusableCellWithIdentifier:valueCellId];
            if (!vc) vc = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
                                                reuseIdentifier:valueCellId];
            vc.accessoryView = nil;
            vc.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
            vc.textLabel.text = @"自动验证面容";
            vc.textLabel.textColor = [UIColor labelColor];
            vc.textLabel.font = [UIFont systemFontOfSize:17];
            NSTimeInterval d = [ALStore shared].autoBioDelay;
            NSString *detail = (d < 0) ? @"已关闭"
                : (d <= 0) ? @"立即"
                : [NSString stringWithFormat:@"延迟 %.0f 秒", (double)(NSInteger)d];
            vc.detailTextLabel.text = detail;
            vc.detailTextLabel.textColor = [UIColor secondaryLabelColor];
            return vc;
        }
        if (indexPath.row == 2) {
            // 应用内双指双击手势开关
            cell.textLabel.text = @"双指双击呼出设置面板";
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            UISwitch *gsw = [[UISwitch alloc] init];
            gsw.on = [ALStore shared].gestureEnabled;
            [gsw addTarget:self action:@selector(gestureSwitchChanged:)
          forControlEvents:UIControlEventValueChanged];
            cell.accessoryView = gsw;
            return cell;
        }
        cell.textLabel.text = @"面容 / 触控 ID 解锁";
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        UISwitch *sw = [[UISwitch alloc] init];
        if (![self biometricsUsable]) {
            cell.textLabel.textColor = [UIColor secondaryLabelColor];
            sw.on = NO;
            sw.enabled = NO;
        } else {
            sw.on = [ALStore shared].biometricEnabled;
            [sw addTarget:self action:@selector(bioSwitchChanged:)
         forControlEvents:UIControlEventValueChanged];
        }
        cell.accessoryView = sw;
    } else if (indexPath.section == 1) {
        static NSArray *titles;
        static NSArray *values;
        if (!titles) {
            titles = @[@"立即锁定", @"15 秒后", @"1 分钟后", @"5 分钟后"];
            values = @[@0, @15, @60, @300];
        }
        cell.textLabel.text = titles[indexPath.row];
        if ([values[indexPath.row] doubleValue] == [ALStore shared].graceInterval) {
            cell.accessoryType = UITableViewCellAccessoryCheckmark;
        }
    } else if (indexPath.section == 2) {
        cell.textLabel.text = @"修改应用锁密码";
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    } else {
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.textLabel.text = indexPath.row == 0
            ? [NSString stringWithFormat:@"版本 %@", kTweakVersion]
            : @"重构自 tien0246/ProtectedApp";
        cell.textLabel.textColor = [UIColor secondaryLabelColor];
        cell.textLabel.font = [UIFont systemFontOfSize:14];
    }
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (indexPath.section == 0 && indexPath.row == 1) {
        [self showAutoBioDelaySheet];
    } else if (indexPath.section == 1) {
        static NSArray *values;
        if (!values) values = @[@0, @15, @60, @300];
        [ALStore shared].graceInterval = [values[indexPath.row] doubleValue];
        [self.tableView reloadData];
    } else if (indexPath.section == 2) {
        [self showChangePINFlow];
    }
}

- (void)bioSwitchChanged:(UISwitch *)sw {
    if (sw.on && ![self biometricsUsable]) {
        sw.on = NO;
        return;
    }
    [ALStore shared].biometricEnabled = sw.on;
}

- (void)gestureSwitchChanged:(UISwitch *)sw {
    [ALStore shared].gestureEnabled = sw.on;
    // 立即生效: 关闭时移除全部手势, 开启时重新挂载
    [[ALManager shared] attachInAppGesture];
}

/* 修改密码: 复用自带数字键盘的三步流程 (当前密码 → 新密码 → 确认)。
 * 旧方案用 UIAlertController 挂 3 个数字键盘输入框: 弹窗自动聚焦后系统键盘
 * 挡住操作按钮, 数字键盘又没有回车键无法收起, 导致整个应用触控死锁, 故弃用。 */
- (void)showChangePINFlow {
    if ([ALStore shared].isLockedOut) {
        [self showAlert:@"暂时无法修改" msg:@"错误次数过多，请稍后再试"];
        return;
    }
    ALLockViewController *change = [[ALLockViewController alloc] init];
    change.title = @"修改应用锁密码";
    change.purpose = ALVerifyChangePIN;
    change.setupStep = 0;
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:change];
    nav.modalPresentationStyle = UIModalPresentationPageSheet;
    [self presentViewController:nav animated:YES completion:nil];
}

- (void)showAutoBioDelaySheet {
    UIAlertController *sheet =
        [UIAlertController alertControllerWithTitle:@"自动验证面容"
                                            message:@"打开应用出现锁屏后，等待多久自动刷脸。\n等待期间可输入密码，或点右上角齿轮进设置。"
                                     preferredStyle:UIAlertControllerStyleActionSheet];
    NSArray *titles = @[@"关闭自动验证", @"立即验证", @"延迟 2 秒", @"延迟 5 秒"];
    NSArray *values = @[@(-1.0), @0.0, @2.0, @5.0];
    [titles enumerateObjectsUsingBlock:^(NSString *t, NSUInteger i, BOOL *stop) {
        [sheet addAction:[UIAlertAction actionWithTitle:t
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction *action) {
            [ALStore shared].autoBioDelay = [values[i] doubleValue];
            [self.tableView reloadData];
        }]];
    }];
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    // iPad 上 ActionSheet 必须指定锚点, 否则直接崩溃 (iPhone 上无 popover 对象, 不受影响)
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = self.tableView;
        sheet.popoverPresentationController.sourceRect =
            CGRectMake(self.tableView.bounds.size.width / 2.0,
                       self.tableView.bounds.size.height / 2.0, 1.0, 1.0);
        sheet.popoverPresentationController.permittedArrowDirections = 0;
    }
    [self presentViewController:sheet animated:YES completion:nil];
}

- (void)showAlert:(NSString *)title msg:(NSString *)msg {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:title
                                                               message:msg
                                                        preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

@end

#pragma mark - ALManager (核心状态机)

@implementation ALManager {
    BOOL _bootstrapped;
}

+ (instancetype)shared {
    static ALManager *s = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ s = [[ALManager alloc] init]; });
    return s;
}

- (void)bootstrapIfNeeded {
    if (_bootstrapped) return;
    _bootstrapped = YES;

    [ALStore shared]; // 触发加载 + 旧版密码迁移

    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc addObserver:self selector:@selector(handleResignActive)
               name:UIApplicationWillResignActiveNotification object:nil];
    [nc addObserver:self selector:@selector(handleEnterBackground)
               name:UIApplicationDidEnterBackgroundNotification object:nil];
    [nc addObserver:self selector:@selector(handleForeground)
               name:UIApplicationWillEnterForegroundNotification object:nil];
    [nc addObserver:self selector:@selector(handleBecomeActive)
               name:UIApplicationDidBecomeActiveNotification object:nil];

    // 冷启动一律先锁定 (未设密码则进入首次设置流程)。
    // 直接强制锁定, 不走 evaluateRelock (其需要 lastResignDate 才判定, 而冷启动该值为 nil)
    self.locked = YES;
    [self ensureLockWindow];
    [self.lockVC showLockUI];
    [self.lockWindow makeKeyAndVisible];
    [self attachInAppGesture];
}

- (void)handleResignActive {
    self.lastResignDate = [NSDate date];
    [self prepareCover];   // 立即遮盖, 防止后台快照泄露内容
}

- (void)handleEnterBackground {
    [self prepareCover];
    // "立即锁定"时, 退后台即进入完整锁定态:
    // 1) 后台快照显示的是锁定界面而非模糊遮盖; 2) 不依赖回前台通知兜底
    if (![ALStore shared].hasPIN) return;
    if ([ALStore shared].graceInterval > 0) return;
    self.locked = YES;
    [self ensureLockWindow];
    [self.lockVC showLockUI];
    [self.lockWindow makeKeyAndVisible];
}

- (void)handleForeground {
    [self evaluateRelock];
    [self attachInAppGesture];
}

- (void)handleBecomeActive {
    [self evaluateRelock];
    [self attachInAppGesture];
}

/* 回前台判定: 已锁定 → 保持锁定;
 * 未锁定时, 只有"解锁后确实离开过前台"才按宽限期判定是否重锁。
 * lastResignDate == nil 表示解锁后从未离开 (或被 unlockSucceeded 清空),
 * 此时的 DidBecomeActive 属于虚假事件 (系统弹窗/控制中心等触发), 不得重锁。
 * 冷启动的强制锁定由 bootstrapIfNeeded 直接执行, 不经过本方法。 */
- (void)evaluateRelock {
    if (self.isLocked) {
        [self ensureLockWindow];
        [self.lockVC showLockUI];
        [self.lockWindow makeKeyAndVisible];
        return;
    }
    if (self.lastResignDate == nil) return;

    NSTimeInterval grace = [ALStore shared].graceInterval;
    NSDate *now = [NSDate date];
    BOOL needLock = (grace <= 0)
                 || ([now timeIntervalSinceDate:self.lastResignDate] >= grace);
    if (needLock) {
        [self ensureLockWindow];
        self.locked = YES;
        [self.lockVC showLockUI];
        [self.lockWindow makeKeyAndVisible];
    } else if (self.lockWindow && !self.lockWindow.hidden) {
        // 宽限期内快速返回, 收起遮盖
        self.lockWindow.hidden = YES;
    }
}

/* 退后台: 只显示模糊遮盖(无密码盘), 防止 App 切换器缩略图泄露界面 */
- (void)prepareCover {
    [self ensureLockWindow];
    [self.lockVC prepareCover];
    [self.lockWindow makeKeyAndVisible];
}

- (void)unlockSucceeded {
    [[ALStore shared] clearLockState];
    self.locked = NO;
    self.lastResignDate = nil; // ★ 关键: 清空陈旧的离开时间戳,
        // 否则解锁后任何一次 DidBecomeActive (系统弹窗/控制中心等触发)
        // 都会因"离开超过宽限期"的误判而立刻重新上锁
    [self.lockVC prepareCover];
    UIWindow *w = self.lockWindow;
    [UIView animateWithDuration:0.15 animations:^{ w.alpha = 0.0; }
                     completion:^(BOOL finished) { w.hidden = YES; w.alpha = 1.0; }];
    // 解锁后立即挂载双指双击手势, 不必等下一次切前台 (key window 可能已变化)
    dispatch_async(dispatch_get_main_queue(), ^{ [self attachInAppGesture]; });
}

#pragma mark 窗口

- (UIWindowScene *)activeScene {
    NSMutableArray<UIWindowScene *> *all = [NSMutableArray array];
    for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
        if ([s isKindOfClass:[UIWindowScene class]]) [all addObject:(UIWindowScene *)s];
    }
    for (UIWindowScene *s in all) {
        if (s.activationState == UISceneActivationStateForegroundActive) return s;
    }
    return all.firstObject;
}

- (void)ensureLockWindow {
    UIWindowScene *scene = [self activeScene];
    if (self.lockWindow) { // 全进程复用同一个锁定窗口
        // 早期(scene 尚未连接)创建的无 scene 窗口在 scene-based 应用中不显示, 此处补挂
        if (scene && !self.lockWindow.windowScene) self.lockWindow.windowScene = scene;
        return;
    }
    UIWindow *w = nil;
    if (scene) {
        w = [[UIWindow alloc] initWithWindowScene:scene];
    } else {
        w = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    }
    w.windowLevel = UIWindowLevelAlert + 100.0;
    w.backgroundColor = [UIColor clearColor];
    self.lockVC = [[ALLockViewController alloc] init];
    w.rootViewController = self.lockVC;
    self.lockWindow = w;
}

#pragma mark 应用内手势与设置

- (UIWindow *)appKeyWindow {
    for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
        if (![s isKindOfClass:[UIWindowScene class]]) continue;
        for (UIWindow *w in ((UIWindowScene *)s).windows) {
            if ([w isKeyWindow] && w != self.lockWindow) return w;
        }
    }
    UIWindow *legacy = [UIApplication sharedApplication].keyWindow;
    return (legacy && legacy != self.lockWindow) ? legacy : nil;
}

- (void)attachInAppGesture {
    // 先清理旧手势 (window 集合可能已变化, 每次重建成本极低)
    if (!_inAppTaps) _inAppTaps = [NSMutableArray array];
    for (UITapGestureRecognizer *t in _inAppTaps) {
        if (t.view) [t.view removeGestureRecognizer:t];
    }
    [_inAppTaps removeAllObjects];

    if (self.isLocked) return;
    if (![ALStore shared].gestureEnabled) return;

    /* ★ 挂到所有可见的主层级 window, 而非仅 key window:
     * NTQQ 是多 window 架构, 内容界面所在的 window 未必是 key window,
     * 只挂 key window 会因触摸不经过该 window 而完全失效。
     * 跳过键盘/浮窗等高层级 window, 避免在键盘上双击误触发。 */
    for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
        if (![s isKindOfClass:[UIWindowScene class]]) continue;
        for (UIWindow *w in ((UIWindowScene *)s).windows) {
            if (w == self.lockWindow || w.hidden) continue;
            if (w.windowLevel > UIWindowLevelNormal) continue;
            UITapGestureRecognizer *tap =
                [[UITapGestureRecognizer alloc] initWithTarget:self
                                                        action:@selector(settingsGestureFired)];
            tap.numberOfTapsRequired = 2;
            tap.numberOfTouchesRequired = 2;
            tap.cancelsTouchesInView = NO;
            [w addGestureRecognizer:tap];
            [_inAppTaps addObject:tap];
        }
    }
}

/* 应用内三指双击 → 设置面板 (应用已解锁状态下无需再次验证) */
- (void)settingsGestureFired {
    if (self.isLocked) return;
    UIViewController *top = [self topViewController];
    if (!top) return;
    ALSettingsController *settings =
        [[ALSettingsController alloc] initWithStyle:UITableViewStyleInsetGrouped];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:settings];
    nav.modalPresentationStyle = UIModalPresentationPageSheet;
    [top presentViewController:nav animated:YES completion:nil];
}

- (UIViewController *)topViewController {
    /* 跨 window 寻找真实内容容器: 与手势挂载同理, key window 未必是内容所在 window,
     * 取 windowLevel 最高的可见主 window 作为呈现锚点 */
    UIWindow *best = nil;
    for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
        if (![s isKindOfClass:[UIWindowScene class]]) continue;
        for (UIWindow *w in ((UIWindowScene *)s).windows) {
            if (w == self.lockWindow || w.hidden || !w.rootViewController) continue;
            if (!best || w.windowLevel > best.windowLevel) best = w;
        }
    }
    if (!best) return nil;
    UIViewController *vc = best.rootViewController;
    while (YES) {
        if ([vc isKindOfClass:[UINavigationController class]]) {
            vc = ((UINavigationController *)vc).visibleViewController;
            continue;
        }
        UIViewController *presented = vc.presentedViewController;
        if (presented) { vc = presented; continue; }
        break;
    }
    return vc;
}

@end

#pragma mark - Hook 入口 (纯 ObjC runtime swizzle, 无 CydiaSubstrate 依赖)
/* TrollFools / JailFools 等单应用注入环境中不存在 CydiaSubstrate/ElleKit,
 * 因此不能用 Logos(%hook) —— 这里用 method_setImplementation 直接替换方法实现,
 * 与 NTQQ_AntiRecall 等免 substrate 插件的做法一致。 */

static void (*ALOrig_UIWindow_makeKeyAndVisible)(id, SEL);

static void ALHook_UIWindow_makeKeyAndVisible(UIWindow *self, SEL _cmd) {
    ALOrig_UIWindow_makeKeyAndVisible(self, _cmd);

    // 防递归: 我们自己的锁定窗口调用 makeKeyAndVisible 时不处理
    if (self == [ALManager shared].lockWindow) return;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        [[ALManager shared] bootstrapIfNeeded];
    });
}

__attribute__((constructor)) static void ALDylibEntry(void) {
    // 1) swizzle -[UIWindow makeKeyAndVisible]: 主引导入口
    Class windowCls = objc_getClass("UIWindow");
    Method m = windowCls ? class_getInstanceMethod(windowCls, @selector(makeKeyAndVisible)) : NULL;
    if (m) {
        ALOrig_UIWindow_makeKeyAndVisible = (void (*)(id, SEL))method_getImplementation(m);
        method_setImplementation(m, (IMP)ALHook_UIWindow_makeKeyAndVisible);
    }

    // 2) 兜底引导: 部分 App 不走 makeKeyAndVisible, 用系统通知保证一定生效
    //    (bootstrapIfNeeded 幂等, 可被多个入口安全触发)
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    for (NSString *name in @[
            UIApplicationDidFinishLaunchingNotification,
            UIApplicationDidBecomeActiveNotification,
    ]) {
        [nc addObserverForName:name object:nil queue:nil
                    usingBlock:^(NSNotification * _Nonnull n) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [[ALManager shared] bootstrapIfNeeded];
            });
        }];
    }
}
