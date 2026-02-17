#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
WeChatMsg - 微信聊天记录一键解密导出工具
PySide6 Qt GUI，单 exe 一键完成全流程
"""

import json
import os
import string
import sys
import traceback
from multiprocessing import freeze_support

# 兼容 PyInstaller 打包
if getattr(sys, 'frozen', False):
    _base = sys._MEIPASS
else:
    _base = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _base)

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QProgressBar, QPlainTextEdit,
    QLineEdit, QFileDialog, QRadioButton, QGroupBox
)
from PySide6.QtCore import Qt, QThread, Signal, QUrl
from PySide6.QtGui import QFont, QDesktopServices


def find_decrypted_accounts(search_dir):
    """在指定目录下查找已解密的微信账号目录"""
    accounts = []
    if not os.path.isdir(search_dir):
        return accounts
    for name in os.listdir(search_dir):
        d = os.path.join(search_dir, name)
        if not os.path.isdir(d):
            continue
        info_v4 = os.path.join(d, 'db_storage', 'info.json')
        info_v3 = os.path.join(d, 'Msg', 'info.json')
        if os.path.isfile(info_v4):
            accounts.append((d, 'db_storage', 4))
        elif os.path.isfile(info_v3):
            accounts.append((d, 'Msg', 3))
    return accounts


def find_wechat_install_dirs():
    """扫描本机常见位置查找微信数据目录（无需微信运行）"""
    dirs = []
    seen = set()
    user_profile = os.environ.get('USERPROFILE', '')

    # V4: xwechat_files
    search_roots = []
    if user_profile:
        search_roots.append(os.path.join(user_profile, 'Documents', 'xwechat_files'))
    for drive in string.ascii_uppercase:
        p = f'{drive}:\\xwechat_files'
        if os.path.isdir(p):
            search_roots.append(p)

    for root in search_roots:
        if not os.path.isdir(root):
            continue
        try:
            for sub in os.listdir(root):
                full = os.path.join(root, sub)
                if os.path.isdir(full) and os.path.isdir(os.path.join(full, 'db_storage')):
                    real = os.path.normcase(os.path.abspath(full))
                    if real not in seen:
                        seen.add(real)
                        dirs.append(('v4', full))
        except OSError:
            pass

    # V3: WeChat Files
    if user_profile:
        v3_base = os.path.join(user_profile, 'Documents', 'WeChat Files')
        if os.path.isdir(v3_base):
            try:
                for sub in os.listdir(v3_base):
                    full = os.path.join(v3_base, sub)
                    if os.path.isdir(full) and os.path.isdir(os.path.join(full, 'Msg')):
                        real = os.path.normcase(os.path.abspath(full))
                        if real not in seen:
                            seen.add(real)
                            dirs.append(('v3', full))
            except OSError:
                pass

    return dirs


class WorkerThread(QThread):
    """后台工作线程"""
    log_signal = Signal(str)
    progress_signal = Signal(int)
    status_signal = Signal(str)
    finished_signal = Signal(bool, str)  # (成功, 输出目录)

    def __init__(self, mode='auto', manual_dir='', output_dir=''):
        super().__init__()
        self.mode = mode  # 'auto' or 'export_only'
        self.manual_dir = manual_dir
        self.output_dir_base = output_dir

    def log(self, msg):
        self.log_signal.emit(msg)

    def run(self):
        try:
            if self.mode == 'auto':
                self._run_auto()
            else:
                self._run_export_only()
        except Exception as e:
            self.log(f'\n--- 错误 ---\n{traceback.format_exc()}')
            self.finished_signal.emit(False, '')

    # ==================== 自动模式 ====================

    def _run_auto(self):
        """完整流程：检测微信进程 → 解密数据库 → 导出聊天记录"""
        self.status_signal.emit('正在检测微信进程...')
        self.progress_signal.emit(0)

        from wxManager import Me
        from wxManager.decrypt import get_info_v4, get_info_v3
        from wxManager.decrypt.decrypt_dat import get_decode_code_v4
        from wxManager.decrypt import decrypt_v4, decrypt_v3

        self.log('检测微信 4.x 进程...')
        wx_infos = get_info_v4()

        if not wx_infos:
            self.log('未检测到微信 4.x，尝试微信 3.x...')
            version_list_path = os.path.join(_base, 'wxManager', 'decrypt', 'version_list.json')
            if os.path.exists(version_list_path):
                with open(version_list_path, 'r', encoding='utf-8') as f:
                    version_list = json.load(f)
                wx_infos = get_info_v3(version_list)

        if not wx_infos:
            self.log('未检测到正在运行的微信！')
            self.log('请确保微信已登录且正在运行，或切换到「仅导出」模式。')
            self.finished_signal.emit(False, '')
            return

        self.progress_signal.emit(10)
        all_output_dirs = []

        for idx, wx_info in enumerate(wx_infos):
            self.log(f'\n{"=" * 50}')
            self.log(f'账号 {idx + 1}: {wx_info.nick_name} ({wx_info.wxid})')
            self.log(f'版本: {wx_info.version}')
            self.log(f'微信目录: {wx_info.wx_dir}')

            if not wx_info.key:
                self.log('错误：未找到密钥，请重启微信后再试')
                continue

            is_v4 = hasattr(wx_info, 'raw_keys') and wx_info.raw_keys
            db_version = 4 if is_v4 or (wx_info.key and wx_info.key.startswith('raw:')) else 3

            me = Me()
            me.wx_dir = wx_info.wx_dir
            me.wxid = wx_info.wxid
            me.name = wx_info.nick_name

            if self.output_dir_base:
                output_dir = os.path.join(self.output_dir_base, wx_info.wxid)
            else:
                output_dir = wx_info.wxid

            # ---- 解密 ----
            self.status_signal.emit(f'正在解密 {wx_info.nick_name} 的数据库...')

            if db_version == 4:
                me.xor_key = get_decode_code_v4(wx_info.wx_dir)
                info_data = me.to_json()
                raw_keys = wx_info.raw_keys if hasattr(wx_info, 'raw_keys') else None
                self.log(f'XOR密钥: 0x{me.xor_key:x}')
                self.log('开始解密数据库（微信4.x）...')
                decrypt_v4.decrypt_db_files(
                    wx_info.key, src_dir=wx_info.wx_dir,
                    dest_dir=output_dir, raw_keys=raw_keys
                )
                db_sub_dir = 'db_storage'
            else:
                info_data = me.to_json()
                self.log('开始解密数据库（微信3.x）...')
                decrypt_v3.decrypt_db_files(
                    wx_info.key, src_dir=wx_info.wx_dir,
                    dest_dir=output_dir
                )
                db_sub_dir = 'Msg'

            info_path = os.path.join(output_dir, db_sub_dir, 'info.json')
            os.makedirs(os.path.dirname(info_path), exist_ok=True)
            with open(info_path, 'w', encoding='utf-8') as f:
                json.dump(info_data, f, ensure_ascii=False, indent=4)

            self.log('数据库解密完成！')
            self.progress_signal.emit(40)

            # ---- 导出 ----
            export_path = os.path.join(output_dir, 'export_html')
            result = self._export_account(
                os.path.join(output_dir, db_sub_dir),
                db_version, export_path, wx_info.nick_name
            )
            if result:
                all_output_dirs.append(result)

        self.progress_signal.emit(100)
        self.status_signal.emit('全部完成！')
        self.finished_signal.emit(True, all_output_dirs[0] if all_output_dirs else '')

    # ==================== 仅导出模式 ====================

    def _run_export_only(self):
        """仅导出：从已解密的数据库目录直接导出聊天记录"""
        self.status_signal.emit('正在扫描已解密的数据库...')
        self.progress_signal.emit(0)

        manual_dir = self.manual_dir
        if not manual_dir or not os.path.isdir(manual_dir):
            self.log(f'目录不存在: {manual_dir}')
            self.finished_signal.emit(False, '')
            return

        # 判断用户选择的目录结构
        accounts = []
        info_v4 = os.path.join(manual_dir, 'db_storage', 'info.json')
        info_v3 = os.path.join(manual_dir, 'Msg', 'info.json')

        if os.path.isfile(info_v4):
            accounts.append((manual_dir, 'db_storage', 4))
        elif os.path.isfile(info_v3):
            accounts.append((manual_dir, 'Msg', 3))
        else:
            # 可能是包含多个账号的父目录
            accounts = find_decrypted_accounts(manual_dir)

        if not accounts:
            self.log(f'未在 {manual_dir} 找到已解密的数据库！')
            self.log('期望的目录结构：')
            self.log('  V4: <目录>/db_storage/info.json')
            self.log('  V3: <目录>/Msg/info.json')
            self.log('或父目录下包含多个 wxid_xxx 子目录。')
            self.finished_signal.emit(False, '')
            return

        self.log(f'找到 {len(accounts)} 个已解密的账号')
        all_output_dirs = []

        for idx, (acct_dir, db_sub_dir, db_version) in enumerate(accounts):
            info_path = os.path.join(acct_dir, db_sub_dir, 'info.json')
            try:
                with open(info_path, 'r', encoding='utf-8') as f:
                    info = json.load(f)
                nick = info.get('nickname', os.path.basename(acct_dir))
            except Exception:
                nick = os.path.basename(acct_dir)

            self.log(f'\n{"=" * 50}')
            self.log(f'账号 {idx + 1}: {nick}')
            self.log(f'数据库目录: {os.path.join(acct_dir, db_sub_dir)}')

            if self.output_dir_base:
                export_path = os.path.join(self.output_dir_base, 'export_html')
            else:
                export_path = os.path.join(acct_dir, 'export_html')

            self.progress_signal.emit(5)
            result = self._export_account(
                os.path.join(acct_dir, db_sub_dir),
                db_version, export_path, nick
            )
            if result:
                all_output_dirs.append(result)

        self.progress_signal.emit(100)
        self.status_signal.emit('全部完成！')
        self.finished_signal.emit(True, all_output_dirs[0] if all_output_dirs else '')

    # ==================== 导出逻辑 ====================

    def _export_account(self, db_dir, db_version, export_dir, nick_name):
        """导出单个账号的全部聊天记录为 HTML"""
        self.status_signal.emit(f'正在导出 {nick_name} 的聊天记录...')

        from wxManager import Me, DatabaseConnection
        from exporter import HtmlExporter
        from exporter.config import FileType

        info_path = os.path.join(db_dir, 'info.json')
        if not os.path.isfile(info_path):
            self.log(f'缺少 info.json: {info_path}')
            return None

        me = Me()
        me.load_from_json(info_path)

        conn = DatabaseConnection(db_dir, db_version)
        database = conn.get_interface()
        if not database:
            self.log('数据库初始化失败！请检查路径和数据库文件是否完整。')
            return None

        contacts = database.get_contacts()
        total = len(contacts)
        if total == 0:
            self.log('没有找到联系人。')
            return None

        success = 0
        fail = 0
        skip = 0

        for i, contact in enumerate(contacts):
            contact_dir = os.path.join(
                export_dir, '聊天记录',
                f'{contact.remark}({contact.wxid})'
            )
            html_file = os.path.join(contact_dir, f'{contact.remark}.html')
            if os.path.exists(html_file):
                skip += 1
            else:
                try:
                    exporter = HtmlExporter(
                        database, contact,
                        output_dir=export_dir,
                        type_=FileType.HTML,
                    )
                    exporter.start()
                    success += 1
                except Exception as e:
                    fail += 1
                    self.log(f'  导出失败 [{contact.remark}]: {e}')

            # 更新进度 (40% ~ 95%)
            progress = 40 + int(55 * (i + 1) / total)
            self.progress_signal.emit(min(progress, 95))

            if (i + 1) % 50 == 0:
                self.log(f'  进度: {i + 1}/{total}')

        self.log(f'\n导出完成！成功: {success}  失败: {fail}  跳过: {skip}  总计: {total}')
        abs_export = os.path.abspath(export_dir)
        self.log(f'输出目录: {abs_export}')
        return abs_export


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.output_dir = ''
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('WeChatMsg - 微信聊天记录导出工具')
        self.setMinimumSize(680, 620)
        self.resize(750, 660)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 15, 20, 15)

        # ---- 标题 ----
        title = QLabel('微信聊天记录导出工具')
        title.setFont(QFont('Microsoft YaHei', 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel('支持微信 3.x / 4.0 / 4.1（自动解密 + 导出 HTML）')
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet('color: #666;')
        layout.addWidget(subtitle)

        # ---- 运行模式 ----
        mode_group = QGroupBox('运行模式')
        mode_group.setFont(QFont('Microsoft YaHei', 10))
        mode_layout = QVBoxLayout(mode_group)

        self.radio_auto = QRadioButton('自动检测微信并解密导出（需要微信正在运行）')
        self.radio_auto.setChecked(True)
        self.radio_auto.toggled.connect(self._on_mode_changed)
        mode_layout.addWidget(self.radio_auto)

        self.radio_manual = QRadioButton('仅导出已解密的数据库（无需微信运行）')
        self.radio_manual.toggled.connect(self._on_mode_changed)
        mode_layout.addWidget(self.radio_manual)

        layout.addWidget(mode_group)

        # ---- 数据库目录（手动模式） ----
        self.dir_group = QGroupBox('数据库目录')
        self.dir_group.setFont(QFont('Microsoft YaHei', 10))
        self.dir_group.setEnabled(False)
        dir_layout = QVBoxLayout(self.dir_group)

        dir_row = QHBoxLayout()
        self.dir_input = QLineEdit()
        self.dir_input.setPlaceholderText('选择包含已解密数据库的目录（如 wxid_xxx 文件夹）')
        dir_row.addWidget(self.dir_input, 1)

        self.browse_btn = QPushButton('浏览')
        self.browse_btn.clicked.connect(self._on_browse_dir)
        dir_row.addWidget(self.browse_btn)

        self.scan_btn = QPushButton('自动扫描')
        self.scan_btn.clicked.connect(self._on_scan_decrypted)
        dir_row.addWidget(self.scan_btn)

        dir_layout.addLayout(dir_row)

        self.dir_hint = QLabel('')
        self.dir_hint.setStyleSheet('color: #999; font-size: 12px;')
        dir_layout.addWidget(self.dir_hint)

        layout.addWidget(self.dir_group)

        # ---- 输出目录 ----
        out_group = QGroupBox('输出目录（可选，留空使用默认位置）')
        out_group.setFont(QFont('Microsoft YaHei', 10))
        out_layout = QHBoxLayout(out_group)

        self.output_input = QLineEdit()
        self.output_input.setPlaceholderText('默认输出到数据库同级目录')
        out_layout.addWidget(self.output_input, 1)

        output_browse = QPushButton('浏览')
        output_browse.clicked.connect(self._on_browse_output)
        out_layout.addWidget(output_browse)

        layout.addWidget(out_group)

        # ---- 状态 ----
        self.status_label = QLabel('请选择运行模式，然后点击「一键开始」')
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setFont(QFont('Microsoft YaHei', 11))
        self.status_label.setStyleSheet('color: #333; padding: 6px;')
        layout.addWidget(self.status_label)

        # ---- 开始按钮 ----
        self.start_button = QPushButton('一键开始')
        self.start_button.setFont(QFont('Microsoft YaHei', 14, QFont.Weight.Bold))
        self.start_button.setMinimumHeight(50)
        self.start_button.setStyleSheet('''
            QPushButton {
                background-color: #07C160;
                color: white;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #06AD56;
            }
            QPushButton:disabled {
                background-color: #ccc;
                color: #999;
            }
        ''')
        self.start_button.clicked.connect(self._on_start)
        layout.addWidget(self.start_button)

        # ---- 进度条 ----
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet('''
            QProgressBar {
                border: 1px solid #ddd;
                border-radius: 4px;
                text-align: center;
                height: 22px;
            }
            QProgressBar::chunk {
                background-color: #07C160;
                border-radius: 3px;
            }
        ''')
        layout.addWidget(self.progress_bar)

        # ---- 日志 ----
        log_label = QLabel('运行日志：')
        log_label.setFont(QFont('Microsoft YaHei', 9))
        layout.addWidget(log_label)

        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont('Consolas', 9))
        self.log_text.setStyleSheet('''
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 8px;
            }
        ''')
        layout.addWidget(self.log_text, 1)

        # ---- 打开目录按钮 ----
        self.open_dir_button = QPushButton('打开导出目录')
        self.open_dir_button.setFont(QFont('Microsoft YaHei', 11))
        self.open_dir_button.setMinimumHeight(40)
        self.open_dir_button.setStyleSheet('''
            QPushButton {
                background-color: #1890ff;
                color: white;
                border: none;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #1677cc;
            }
        ''')
        self.open_dir_button.clicked.connect(self._on_open_dir)
        self.open_dir_button.setVisible(False)
        layout.addWidget(self.open_dir_button)

    # ==================== UI 事件 ====================

    def _on_mode_changed(self):
        is_manual = self.radio_manual.isChecked()
        self.dir_group.setEnabled(is_manual)
        if is_manual:
            self.status_label.setText('请选择已解密的数据库目录，然后点击「一键开始」')
        else:
            self.status_label.setText('请确保微信已登录且正在运行，然后点击「一键开始」')
        self.status_label.setStyleSheet('color: #333; padding: 6px;')

    def _on_browse_dir(self):
        d = QFileDialog.getExistingDirectory(self, '选择数据库目录')
        if not d:
            return
        self.dir_input.setText(d)
        self._check_dir(d)

    def _check_dir(self, d):
        """检查目录中是否有已解密的数据库"""
        info_v4 = os.path.join(d, 'db_storage', 'info.json')
        info_v3 = os.path.join(d, 'Msg', 'info.json')
        if os.path.isfile(info_v4):
            self.dir_hint.setText('检测到微信 4.x 已解密数据库')
            self.dir_hint.setStyleSheet('color: #07C160; font-size: 12px;')
        elif os.path.isfile(info_v3):
            self.dir_hint.setText('检测到微信 3.x 已解密数据库')
            self.dir_hint.setStyleSheet('color: #07C160; font-size: 12px;')
        else:
            accounts = find_decrypted_accounts(d)
            if accounts:
                self.dir_hint.setText(f'找到 {len(accounts)} 个已解密的账号')
                self.dir_hint.setStyleSheet('color: #07C160; font-size: 12px;')
            else:
                self.dir_hint.setText('未在该目录找到已解密的数据库')
                self.dir_hint.setStyleSheet('color: #ff4d4f; font-size: 12px;')

    def _on_scan_decrypted(self):
        """自动扫描本地已解密的数据库"""
        self.log_text.clear()
        self.log_text.appendPlainText('正在扫描已解密的数据库...\n')

        # 扫描 exe 所在目录 和 当前工作目录
        scan_dirs = []
        if getattr(sys, 'frozen', False):
            scan_dirs.append(os.path.dirname(sys.executable))
        else:
            scan_dirs.append(os.path.dirname(os.path.abspath(__file__)))
        cwd = os.getcwd()
        if os.path.normcase(cwd) not in [os.path.normcase(d) for d in scan_dirs]:
            scan_dirs.append(cwd)

        all_accounts = []
        for sd in scan_dirs:
            self.log_text.appendPlainText(f'扫描: {sd}')
            accts = find_decrypted_accounts(sd)
            for a in accts:
                all_accounts.append(a)

        if all_accounts:
            self.log_text.appendPlainText(f'\n找到 {len(all_accounts)} 个已解密账号：')
            for i, (acct_dir, sub, ver) in enumerate(all_accounts):
                info_path = os.path.join(acct_dir, sub, 'info.json')
                try:
                    with open(info_path, 'r', encoding='utf-8') as f:
                        info = json.load(f)
                    nick = info.get('nickname', '?')
                    wxid = info.get('username', '?')
                    self.log_text.appendPlainText(f'  [{i + 1}] {nick} ({wxid}) - 微信{"4" if ver == 4 else "3"}.x')
                except Exception:
                    self.log_text.appendPlainText(f'  [{i + 1}] {os.path.basename(acct_dir)}')

            if len(all_accounts) == 1:
                self.dir_input.setText(all_accounts[0][0])
            else:
                # 多个账号取公共父目录
                parent = os.path.dirname(all_accounts[0][0])
                self.dir_input.setText(parent)
            self._check_dir(self.dir_input.text())
        else:
            self.log_text.appendPlainText('\n未找到已解密的数据库。')
            self.log_text.appendPlainText('请使用「浏览」按钮手动选择目录。')
            self.dir_hint.setText('未找到已解密的数据库')
            self.dir_hint.setStyleSheet('color: #ff4d4f; font-size: 12px;')

    def _on_browse_output(self):
        d = QFileDialog.getExistingDirectory(self, '选择输出目录')
        if d:
            self.output_input.setText(d)

    def _on_start(self):
        mode = 'auto' if self.radio_auto.isChecked() else 'export_only'
        manual_dir = self.dir_input.text().strip()
        output_dir = self.output_input.text().strip()

        if mode == 'export_only' and not manual_dir:
            self.status_label.setText('请先选择数据库目录！')
            self.status_label.setStyleSheet('color: #ff4d4f; padding: 6px;')
            return

        self.start_button.setEnabled(False)
        self.start_button.setText('正在运行...')
        self.open_dir_button.setVisible(False)
        self.progress_bar.setValue(0)
        self.log_text.clear()

        self.worker = WorkerThread(mode=mode, manual_dir=manual_dir, output_dir=output_dir)
        self.worker.log_signal.connect(self._append_log)
        self.worker.progress_signal.connect(self.progress_bar.setValue)
        self.worker.status_signal.connect(self.status_label.setText)
        self.worker.finished_signal.connect(self._on_finished)
        self.worker.start()

    def _append_log(self, text):
        self.log_text.appendPlainText(text)

    def _on_finished(self, success, output_dir):
        self.start_button.setEnabled(True)
        self.start_button.setText('一键开始')

        if success:
            self.status_label.setText('全部完成！')
            self.status_label.setStyleSheet('color: #07C160; padding: 6px; font-weight: bold;')
            if output_dir:
                self.output_dir = output_dir
                self.open_dir_button.setVisible(True)
        else:
            self.status_label.setText('运行出错，请查看日志')
            self.status_label.setStyleSheet('color: #ff4d4f; padding: 6px; font-weight: bold;')

    def _on_open_dir(self):
        if self.output_dir and os.path.exists(self.output_dir):
            QDesktopServices.openUrl(QUrl.fromLocalFile(self.output_dir))


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    freeze_support()
    main()
