# 原神解锁FPS限制

ver 6.6 未有新的更新 直接用最新release即可。
<img width="1682" height="994" alt="image" src="https://github.com/user-attachments/assets/c15e8aa2-fc4f-40aa-aec6-472a9375ae21" />



- **2026年3月6日，建议上线改为120帧，不建议再上调**
  
- **最近回归原神，清理了一下代码稍微更新了下**

**6.4版本加入新的选项**
- 打开文件的显示隐藏文件选项找到fps_config.ini
- 若缺少hide项启动游戏会自动写入hide=0(显示窗口)
- 修改hide=1后不会显示窗口直接启动游戏

**HDR（参考 Starward 方案，写入游戏注册表）**
- 在 `fps_config.ini` 的 `[Setting]` 中配置（启动游戏前自动写入注册表）：
  - `hdr=1` 开启 / `hdr=0` 关闭
  - `hdr_max` 峰值亮度（300–2000，默认 1000）
  - `hdr_scene` 场景亮度（100–500，默认 300）
  - `hdr_ui` UI 亮度（150–550，默认 350）
- 需显示器支持 HDR，并在 Windows 显示设置中开启 HDR；多显示器时请将 HDR 显示器设为主屏

**若您觉得好用的话，请给winTEuser老哥的版本
（[点我进入](https://github.com/winTEuser/Genshin_StarRail_fps_unlocker/releases)），点上star进行支持**
 - **要是觉得本项目挺好用的话，也可以点个star支持一下**
 - **本项目仅仅只有解锁FPS的功能，若您还有星铁解锁需求，可以查看 winTEuser 老哥的版本**
 - **如果没有什么意外的话，本项目将跟随 winTEuser老哥版本的部分代码更新**
 - **！重要2：Release里面的版本都是通用的，有时候只是懒得水版本号**
 - **！重要3：如果需要更多功能请下载34736384的unlock_clr,本repo只是简单的解锁并无其它功能**
**感谢Euphony_Facetious以及34736384两位作者的开源**
 - [下载](https://github.com/xiaonian233/genshin-fps-unlock/releases/)
## 自定义参数启动
 - 给unlockfps.exe创建一个快捷方式，在快捷方式的属性处加上需要的参数例如-popupwindow，支持多参数
 - ![image](https://github.com/xiaonian233/genshin-fps-unlock/assets/21072615/de6eeeda-9cf6-4ce4-8559-67011b7d944c)
## 食用指南
 - 第一次运行的话先以管理员运行，然后手动打开游戏，这样解锁器能够获取到游戏路经并保存在配置文件里，这只需要执行一次，以后就可以直接用解锁器启动游戏了
 - 解锁器放哪都行，不封放在原神文件夹
 - 运行之前确保游戏是关闭的
 - 用管理员运行解锁器
 - 解锁器不能关掉
>使用管理员运行是因为游戏必须由解锁器启动，游戏本身就需要管理员权限了，所以负责启动的也是需要的
### 默认热键           PS:按键要按一次改一次，不是长按
- **END** 开/关
- **右ctrl + 上方向键** 增大FPS上限 （+20）
- **右ctrl + 右方向键** 增大FPS上限 （+2）
- **右ctrl + 下方向键** 减少FPS上限 （-20）
- **右ctrl + 左方向键** 减少FPS上限 （-2）
- 源里默认的FPS数值是120

