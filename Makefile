TARGET := iphone:clang:16.5:14.0
ARCHS = arm64
# 如需注入 arm64e 进程(系统应用)可改为: ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

# 以普通动态库方式构建 (非 tweak): 不链接 CydiaSubstrate, 纯 ObjC runtime swizzle,
# 适用于 TrollFools / JailFools 等无 substrate 环境的单应用注入。
LIBRARY_NAME = AppLockPlus
AppLockPlus_FILES = Tweak.m
AppLockPlus_FRAMEWORKS = UIKit Foundation LocalAuthentication Security
AppLockPlus_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
AppLockPlus_LDFLAGS = -install_name @rpath/AppLockPlus.dylib

include $(THEOS_MAKE_PATH)/library.mk
