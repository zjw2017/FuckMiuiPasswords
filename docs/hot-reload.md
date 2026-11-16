# API 102 热重载

设计参照 [hyperwave](https://github.com/leset0ng/hyperwave) 的 `docs/hot-reload.md`。

## 开关与触发

`META-INF/xposed/module.prop` 用 `autoHotReload=true` 选择加入 APK 更新热重载。
**仅声明 `targetApiVersion=102` 不会让模块可重载**——不开这个开关，LSPosed 更新后
只会提示"强制停止作用域中的应用"。框架需实现 API 102 热重载且运行中的模块接受重载。

触发：**全自动**——`adb install -r FuckMiuiPasswords.apk` 后框架把新代码热替换进正在运行的
目标进程，零操作。模块不含任何手动请求通道（无 XposedService/广播接收器）；
若框架不支持或某次重载失败，重启目标进程即可（等效退化路径）。

## 生命周期

`handleHotReloading` 在旧代码代执行（HookTool 的 `ModuleEntrance` 统一分发）：

1. 保存重放注册所需的状态：`{pkg, apk}`（经 `setSavedInstanceState` 由框架转交）。
   只传基础类型/框架对象，不跨代传模块自定义对象。
2. 返回非空 Map 即接受重载；`isHotReloadingAllowed` 返回 false 时框架直接拒绝
   （日志：`FidoEntrance refused to be hot reloaded`）。

`handleHotReloaded` 在新代码代执行：

1. 框架**不会重放** `onModuleLoaded` / `onPackageReady` 等生命周期回调——
   本模块用保存的状态重放 `dispatch(pkg, apk, classLoader)` 重新注册全部 hook。
2. 框架在切换前统一解除旧 Hook 句柄（`HotReloadedParam.getOldHookHandles()`），
   新代注册的是全新句柄，无双钩窗口。
3. 状态恢复带双兜底（跨大版本旧代没存状态时）：进程名推包名（去 `:xxx` 子进程后缀）、
   `ActivityThread.currentApplication()` 反射取 APK 路径。

## 注意事项（实测踩坑）

| 坑 | 表现 | 对策 |
|---|---|---|
| 同 versionCode 重载 | 实测**正常触发**（2.9.1 原样覆盖安装验证） | 无需升版本；早期"被拒"实为 isHotReloadingAllowed 判定 bug 的误诊 |
| 旧代码代没有 `onHotReloading` | 首次升级拒绝/缺状态 | 装一次后重启目标进程（或重启设备），后续更新即可热重载 |
| `isHotReloadingAllowed` 的包名参数为空 | 热重载代里框架不再调 `onPackageLoaded` | 以进程名为判定基准 |
| 共享进程包名污染 | `com.miui.contentcatcher` 借用密码管理进程，ready 事件互相串 | 分发/判定按进程名（`ActivityThread.currentProcessName`） |
| Greezer 冻结广播 | 手动广播无响应（`need cached broadcast`） | 先 force-stop 模块 app 再广播 |

## 验证

```sh
adb logcat -s FuckMiuiPasswords | grep -E "hot re|SHORT|clientData|NetHook"
```

安装新版后预期（零操作）：

```
FuckMiuiPasswords: hot reloading: save state pkg=com.fido.asm apk=/product/app/FidoAuthen2/...
FuckMiuiPasswords: hot reloaded: pkg=com.fido.asm apk=...
FuckMiuiPasswords: SHORT-CIRCUIT p2.e->a(String,String,String,boolean,g2.l)
FuckMiuiPasswords: clientData hook: o2.b->e (carrier)
FuckMiuiPasswords: NetHook installed ...
```

且 LSPosed **不再**提示"强制停止作用域中的应用"。
