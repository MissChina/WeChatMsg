# wxManager 使用教程

> 最新支持版本：**微信 4.1.5.16**（同时兼容 3.x 和 4.0）

## 环境准备

- Windows 10/11
- Python 3.10+
- 微信 PC 版已登录

```bash
# 安装依赖
pip install -r requirements.txt
```

## 第一步：解密数据库

确保微信正在运行且已登录，然后执行：

```bash
cd WeChatMsg
python example/1-decrypt.py
```

运行成功后会在当前目录生成 `wxid_xxx/` 文件夹：
- 微信 4.x → `wxid_xxx/db_storage/`
- 微信 3.x → `wxid_xxx/Msg/`

## 第二步：一键导出（推荐）

```bash
python example/export_all.py
```

自动检测已解密的账号，批量导出所有联系人的 HTML 聊天记录（含图片、视频、文件、语音）。

导出结果在 `wxid_xxx/export_html/聊天记录/` 下，用浏览器打开 `.html` 文件即可查看。

特性：
- 自动检测所有已解密的微信账号（支持 3.x 和 4.x）
- 增量导出：已导出的联系人自动跳过
- 图片自动解密（微信 4.x 的 AES 加密图片）

## 第三步：高级用法

### 查看联系人

修改 `2-contact.py` 中的 `db_dir` 为第一步得到的数据库路径：

```python
db_dir = 'wxid_xxx/db_storage'  # 微信4.x
db_version = 4
```

```bash
python example/2-contact.py
```

### 按联系人导出

修改 `3-exporter.py` 中的参数：

```python
db_dir = 'wxid_xxx/db_storage'  # 数据库路径
db_version = 4
wxid = 'wxid_00112233'          # 目标联系人wxid
output_dir = './data/'           # 输出目录
```

```bash
python example/3-exporter.py
```

### 支持的导出格式

| 格式 | 说明 |
|------|------|
| HTML | 还原微信聊天界面，支持图片/视频/语音/文件 |
| TXT  | 纯文本 |
| CSV  | 表格格式 |
| Word | docx文档 |
| Markdown | md文档 |
| Excel | xlsx表格 |

### 筛选导出

```python
from wxManager import MessageType

exporter = HtmlExporter(
    database, contact,
    output_dir=output_dir,
    type_=FileType.HTML,
    message_types={MessageType.Text, MessageType.Image},  # 仅导出文本和图片
    time_range=['2025-01-01 00:00:00', '2026-01-01 00:00:00'],  # 日期范围
    group_members={'wxid_a', 'wxid_b'}  # 群聊中仅导出指定成员
)
```
