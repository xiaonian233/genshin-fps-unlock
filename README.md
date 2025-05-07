# 原神解锁FPS限制

ver 5.6 未有新的更新，直接用上一版本即可
![RND1`QOHE)L%J%~M $`2RIS](https://github.com/user-attachments/assets/abe99c22-3aa9-41b2-8c9e-04ec0144259c)





**若您觉得好用的话，请给 winTEuser 老哥的版本
（[点我进入](https://github.com/winTEuser/Genshin_StarRail_fps_unlocker/releases)），点上star进行支持**
 - **要是觉得本项目挺好用的话，也可以点个star支持一下**
 - **本项目仅仅只有解锁FPS的功能，若您还有星铁解锁需求，可以查看 winTEuser 老哥的版本**
 - **如果没有什么意外的话，本项目将跟随 winTEuser老哥 版本的代码更新**

**4.6版本开始加入最小化版本 即如果没有错误产生，将不会出现控制台窗口（可能会有bug）如果有问题请提交issue，最小化版本和普通版本可以互相替换使用**

 - **！重要：4.3以下版本暂不支持**
 - **！重要2：Release里面的版本都是通用的，有时候只是懒得水版本号**
 - **！重要3：如果需要更多功能请下载34736384的unlock_clr,本repo只是简单的解锁并无其它功能**
**感谢Euphony_Facetious以及34736384两位作者的开源**

 - 工作原理通过**WriteProcessMemory**把FPS数值写进游戏
 - 不需要通过驱动进行读写操作
 - 支持国服和外服
 - 理论上支持后续版本，不需要更新源码
 - [下载](https://github.com/xiaonian233/genshin-fps-unlock/releases/)
## 自定义参数启动
 - 给unlockfps.exe创建一个快捷方式，在快捷方式的属性处加上需要的参数例如-popupwindow，支持多参数
 - ![image](https://github.com/xiaonian233/genshin-fps-unlock/assets/21072615/de6eeeda-9cf6-4ce4-8559-67011b7d944c)
## 食用指南
 - 第一次运行的话先以管理员运行，然后手动打开游戏，这样解锁器能够获取到游戏路经并保存在配置文件里，这只需要执行一次，以后就可以直接用解锁器启动游戏了
 - 解锁器放哪都行
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

## 注意
- 已经在新号上测试了两星期，目前并没有任何异常，冒险等级30
- 使用未认证的第三方软件修改游戏数据是违反了协议条款的，后果自负
- 想要更改热键的话，修改下源里开头的定义 （[热键码](http://cherrytree.at/misc/vk.htm)）
- 至于为啥我没写成能在和游戏同一个目录下运行是因为游戏登录的时候会进行文件完整性检测，如果游戏目录内有其他文件也会当做是游戏的文件进行检测。如果把解锁器和游戏放一起的话游戏会把解锁器当成游戏文件检测，从而导致报错（31-4302）
- 要转载的话随便，毕竟开源，可以的话就注明下出处
- 这么个破工具请不要拿去倒卖
# Sponsor/感谢赞助
<a href="https://yxvm.com/aff.php?aff=650" target="_blank"><img src="https://i.postimg.cc/XvT30P5J/image.png" width="250"/></a>
[NodeSupport](https://github.com/NodeSeekDev/NodeSupport) Sponsored this project

