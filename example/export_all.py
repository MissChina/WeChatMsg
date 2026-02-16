#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
一键导出微信聊天记录（含图片解密）
自动检测已解密的微信账号，批量导出所有联系人的HTML聊天记录
"""

import json
import os
import shutil
import sys
import time
from multiprocessing import freeze_support

# 修复Windows控制台Unicode输出问题（联系人昵称含emoji）
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from wxManager import DatabaseConnection, Me
from exporter import HtmlExporter
from exporter.config import FileType


def find_wx_accounts():
    """自动扫描已解密的微信账号"""
    accounts = []
    for d in os.listdir('.'):
        info_v4 = os.path.join(d, 'db_storage', 'info.json')
        info_v3 = os.path.join(d, 'Msg', 'info.json')
        if os.path.isfile(info_v4):
            accounts.append((d, 'db_storage', 4))
        elif os.path.isfile(info_v3):
            accounts.append((d, 'Msg', 3))
    return accounts


def export_account(wxid_dir, db_sub_dir, db_version, clean=False):
    """导出单个微信账号的聊天记录"""
    db_dir = os.path.join(wxid_dir, db_sub_dir)
    output_dir = os.path.join(wxid_dir, 'export_html')
    info_json = os.path.join(db_dir, 'info.json')

    # 1. 加载配置
    me = Me()
    me.load_from_json(info_json)
    print(f'用户：{me.name} ({me.wxid})')
    print(f'微信目录：{me.wx_dir}')
    print(f'XOR密钥：0x{me.xor_key:x}')

    # 2. 清理旧导出（仅在clean模式下）
    if clean and os.path.exists(output_dir):
        print(f'清理旧导出目录：{output_dir}')
        shutil.rmtree(output_dir, ignore_errors=True)

    # 3. 连接数据库
    conn = DatabaseConnection(db_dir, db_version)
    database = conn.get_interface()
    if not database:
        print('数据库初始化失败！请检查路径或数据库版本')
        return

    # 4. 获取所有联系人并导出
    contacts = database.get_contacts()
    total = len(contacts)
    success = 0
    fail = 0
    skip = 0
    st = time.time()

    for i, contact in enumerate(contacts):
        # 跳过已经成功导出的联系人
        contact_dir = os.path.join(output_dir, '聊天记录', f'{contact.remark}({contact.wxid})')
        html_file = os.path.join(contact_dir, f'{contact.remark}.html')
        if os.path.exists(html_file):
            skip += 1
            continue
        print(f'[{i + 1}/{total}] {contact.remark} ({contact.wxid})')
        try:
            exporter = HtmlExporter(
                database, contact,
                output_dir=output_dir,
                type_=FileType.HTML,
            )
            exporter.start()
            success += 1
        except Exception as e:
            fail += 1
            print(f'  导出失败：{e}')

    et = time.time()
    print(f'\n导出完成！成功：{success}，失败：{fail}，跳过：{skip}，总计：{total}')
    print(f'耗时：{et - st:.1f}s')
    print(f'输出目录：{os.path.abspath(output_dir)}')


def main():
    accounts = find_wx_accounts()

    if not accounts:
        print('未找到已解密的微信数据库！')
        print('请先运行 1-decrypt.py 解密数据库')
        return

    print(f'发现 {len(accounts)} 个已解密的微信账号：')
    for i, (wxid_dir, sub_dir, ver) in enumerate(accounts):
        info_path = os.path.join(wxid_dir, sub_dir, 'info.json')
        with open(info_path, 'r', encoding='utf-8') as f:
            info = json.load(f)
        name = info.get('nickname', wxid_dir)
        print(f'  [{i + 1}] {name} ({wxid_dir}) - 微信{ver}.x')

    print()

    # 逐个导出
    for wxid_dir, sub_dir, ver in accounts:
        print(f'\n{"=" * 60}')
        export_account(wxid_dir, sub_dir, ver)


if __name__ == '__main__':
    freeze_support()
    main()
