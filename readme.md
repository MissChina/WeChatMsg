## 支持微信 3.x / 4.0 / 4.1（最新测试版本：4.1.5.16）

[点击查看详细设计文档](https://blog.lc044.love/post/13)

<h1 align="center">我的数据我做主</h1>
<div align="center">
    <a href="https://github.com/LC044/WeChatMsg/stargazers">
        <img src="https://img.shields.io/github/stars/LC044/WeChatMsg.svg" />
    </a>
    <a href="https://memotrace.cn/" target="_blank">
        <img alt="GitHub forks" src="https://img.shields.io/github/forks/LC044/WeChatMsg?color=eb6ea5">
    </a>
    <a href="https://memotrace.cn/" target="_blank">
        <img src="https://img.shields.io/badge/WeChat-留痕-blue.svg">
    </a>
    <a target="_blank" href="https://memotrace.cn/">
        <img alt="Hits" src="https://hits.b3log.org/LC044/memotrace.svg">
    </a>
    <a href="https://memotrace.cn/" target="_blank">
        <img src="https://img.shields.io/github/license/LC044/WeChatMsg" />
    </a>
    <a href="https://github.com/LC044/WeChatMsg/releases" target="_blank">
        <img alt="GitHub release (with filter)" src="https://img.shields.io/github/v/release/LC044/WeChatMsg">
    </a>
    <a href="https://memotrace.cn/" target="_blank">
        <img alt="GitHub all releases" src="https://img.shields.io/github/downloads/LC044/WeChatMsg/total?color=3eb370">
    </a>
</div>

<div align="center">
    <a href="https://memotrace.cn/"><img src="https://memotrace.cn/img/logo%20-%20%E5%89%AF%E6%9C%AC.png" height="240"/></a>
</div>

---

# 快速开始

## 方式一：exe直接运行

下载地址：
- GitHub Releases：[https://github.com/LC044/WeChatMsg/releases](https://github.com/LC044/WeChatMsg/releases)
- 官网：[https://memotrace.cn/](https://memotrace.cn/)

下载打包好的exe可执行文件，双击即可运行。

> 若出现闪退请右击选择管理员身份运行；杀毒软件提示有风险选择略过即可。

## 方式二：源码运行

### 环境要求

- Windows 10/11
- Python 3.10+
- 微信 PC 版已登录（解密时需要微信在运行状态）

### 安装

```bash
git clone https://github.com/LC044/WeChatMsg.git
cd WeChatMsg
pip install -r requirements.txt
```

### 使用（只需两步）

**第一步：解密数据库**（需要微信正在运行）

```bash
python example/1-decrypt.py
```

**第二步：一键导出聊天记录**（含图片、视频、语音、文件）

```bash
python example/export_all.py
```

导出完成后，打开 `wxid_xxx/export_html/聊天记录/` 下的 `.html` 文件即可在浏览器中查看。

> 更多用法（按联系人导出、筛选消息类型、多种导出格式）请查看 [使用示例](./example/README.md)

### 常见问题

| 问题 | 解决方案 |
|------|----------|
| key 为 None | 重启微信后重试，确保微信已登录且正在运行 |
| 解密后数据库为空 | 检查微信数据目录路径是否正确 |
| 图片显示不出来 | 确认微信数据目录中有 `msg/attach` 文件夹 |
| 安装依赖报错 | 确保 Python 版本 >= 3.10，尝试 `pip install --upgrade pip` |

---

# 功能

- 🔒️🔑🔓️Windows本地微信数据库（支持微信3.x / 4.0 / 4.1）
- 还原微信聊天界面
    - 🗨文本✅
    - 🏝图片✅
    - 拍一拍等系统消息✅
- 导出数据
  - 批量导出数据✅
  - 导出联系人✅
  - sqlite数据库✅
  - HTML✅
    - 文本、图片、视频、表情包、语音、文件、分享链接、系统消息、引用消息、合并转发的聊天记录、转账、音视频通话、位置分享、名片、小程序、视频号
    - 支持时间轴跳转
    - 引用消息可定位到原文
    - 分享链接、小程序支持超链接跳转
    - 合并转发的聊天记录支持展开
  - CSV文档✅
  - TXT文档✅
  - Word文档✅
- 分析聊天数据，做成[可视化年报](https://memotrace.cn/demo.html)

---

## 2024年度报告

### 预览

[个人年度报告在线预览](https://memotrace.cn/2024/single/)

[双人年度报告在线预览](https://memotrace.cn/2024Report/)

手机可以扫码观看

<img src="/doc/images/qrcode0.png" height="300px"/>

![](/doc/images/demo1.gif)

### 源码地址

[https://github.com/LC044/AnnualReport](https://github.com/LC044/AnnualReport)

---
> \[!IMPORTANT]
> 
> 声明：该项目有且仅有一个目的：“留痕”——我的数据我做主，前提是“我的数据”其次才是“我做主”，禁止任何人以任何形式将其用于任何非法用途，对于使用该程序所造成的任何后果，所有创作者不承担任何责任🙄<br>
> 该软件不能找回删除的聊天记录，任何企图篡改微信聊天数据的想法都是无稽之谈。<br>
> 本项目所有功能均建立在”前言“的基础之上，基于该项目的所有开发者均不能接受任何有悖于”前言“的功能需求，违者后果自负。<br>
> 如果该项目侵犯了您或您产品的任何权益，请联系我删除<br>
> 软件贩子勿扰，违规违法勿扰，二次开发请务必遵守开源协议

[![Star History Chart](https://api.star-history.com/svg?repos=LC044/WeChatMsg&type=Date)](https://star-history.com/?utm_source=bestxtools.com#LC044/WeChatMsg&Date)

# 🤝贡献者

<a href="https://github.com/lc044/wechatmsg/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=lc044/wechatmsg" />
</a>

## 赞助者名单

感谢以下赞助者的慷慨支持：

- [STDquantum](https://github.com/STDquantum)
- [xuanli](https://github.com/xuanli)
- [无名路人](https://github.com/wumingluren)
- [时鹏亮](https://shipengliang.com)

# 🎄温馨提示

如果您在使用该软件的过程中

* 发现新的bug
* 有新的功能诉求
* 操作比较繁琐
* 觉得UI不够美观
* 等其他给您造成困扰的地方

请提起[issue](https://github.com/LC044/WeChatMsg/issues)，我将尽快为您解决问题

如果您是一名开发者，有新的想法或建议，欢迎[fork](https://github.com/LC044/WeChatMsg/forks)
该项目并发起[PR](https://github.com/LC044/WeChatMsg/pulls)，我将把您的名字写入贡献者名单中

# 联系方式

如果您遇到了问题，可以添加QQ群寻求帮助，由于精力有限，不能回答所有问题，所以还请您仔细阅读文档之后再考虑是否入群

## 加群方式

1. 关注官方公众号，回复：联系方式
2. QQ扫码入群

后续更新将会在公众号同步发布
<div>
  <img src="https://blog.lc044.love/static/img/b8df8c594a4cabaa0a62025767a3cfd9.weixin.webp">
</div>

# License

WeChatMsg is licensed under [MIT](./LICENSE).

Copyright © 2022-2026 by SiYuan.
