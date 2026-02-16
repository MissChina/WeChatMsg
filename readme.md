# WeChatMsg - 微信聊天记录导出工具

> 支持微信 3.x / 4.0 / 4.1（最新测试版本：**4.1.5.16**）

提取并解密 Windows 微信本地数据库，一键导出全部聊天记录为 HTML（含图片、视频、语音、文件）。

## 快速开始

### 方式一：下载 exe 直接运行

前往 [Releases](https://github.com/MissChina/WeChatMsg/releases) 下载最新版本的压缩包，解压后：

1. 确保微信已登录且正在运行
2. 双击 `WeChatMsg-decrypt.exe` 解密数据库
3. 双击 `WeChatMsg-export.exe` 一键导出聊天记录
4. 打开 `wxid_xxx/export_html/聊天记录/` 下的 `.html` 文件即可在浏览器中查看

> 若出现闪退请右击选择管理员身份运行；杀毒软件提示有风险选择略过即可。

### 方式二：源码运行

**环境要求：** Windows 10/11、Python 3.10+、微信 PC 版已登录

```bash
git clone https://github.com/MissChina/WeChatMsg.git
cd WeChatMsg
pip install -r requirements.txt
```

**只需两步：**

```bash
# 第一步：解密数据库（需要微信正在运行）
python example/1-decrypt.py

# 第二步：一键导出聊天记录（含图片、视频、语音、文件）
python example/export_all.py
```

导出完成后，打开 `wxid_xxx/export_html/聊天记录/` 下的 `.html` 文件即可在浏览器中查看。

> 更多用法（按联系人导出、筛选消息类型、多种导出格式）请查看 [使用示例](./example/README.md)

## 功能

- 解密 Windows 本地微信数据库（支持微信 3.x / 4.0 / 4.1）
- 自动提取数据库密钥（codec_ctx 策略 + YARA 扫描）
- 图片自动解密（微信 4.x AES 加密图片）
- 批量导出所有联系人聊天记录
- 增量导出：已导出的联系人自动跳过

**导出格式：**

| 格式 | 说明 |
|------|------|
| HTML | 还原微信聊天界面，支持图片/视频/语音/文件/表情包/引用/合并转发 |
| TXT | 纯文本 |
| CSV | 表格格式 |
| Word | docx 文档 |
| Markdown | md 文档 |
| Excel | xlsx 表格 |

## 常见问题

| 问题 | 解决方案 |
|------|----------|
| key 为 None | 重启微信后重试，确保微信已登录且正在运行 |
| 解密后数据库为空 | 检查微信数据目录路径是否正确 |
| 图片显示不出来 | 确认微信数据目录中有 `msg/attach` 文件夹 |
| 安装依赖报错 | 确保 Python 版本 >= 3.10，尝试 `pip install --upgrade pip` |

## 致谢

- 原项目：[LC044/WeChatMsg](https://github.com/LC044/WeChatMsg)
- PC微信工具：[PyWxDump](https://github.com/xaoyaoo/PyWxDump)

## License

[MIT](./LICENSE)
