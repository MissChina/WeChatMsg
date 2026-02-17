#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
WeChatMsg - 微信聊天记录一键解密导出工具
PySide6 Qt GUI，单 exe 一键完成全流程
"""

import json
import os
import shutil
import sys
import time
import traceback
from multiprocessing import freeze_support

# 兼容 PyInstaller 打包
if getattr(sys, 'frozen', False):
    _base = sys._MEIPASS
else:
    _base = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _base)

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QLabel, QPushButton, QProgressBar, QPlainTextEdit,
    QMessageBox
)
from PySide6.QtCore import Qt, QThread, Signal, QUrl
from PySide6.QtGui import QFont, QDesktopServices


class WorkerThread(QThread):
    """后台工作线程：检测微信 → 解密数据库 → 导出聊天记录"""
    log_signal = Signal(str)
    progress_signal = Signal(int)
    status_signal = Signal(str)
    finished_signal = Signal(bool, str)  # (成功, 输出目录)

    def log(self, msg):
        self.log_signal.emit(msg)

    def run(self):
        try:
            self._run_pipeline()
        except Exception as e:
            self.log(f'\n--- 错误 ---\n{traceback.format_exc()}')
            self.finished_signal.emit(False, '')

    def _run_pipeline(self):
        # ========== 第1步：检测微信进程并提取密钥 ==========
        self.status_signal.emit('正在检测微信进程...')
        self.progress_signal.emit(0)

        from wxManager import Me
        from wxManager.decrypt import get_info_v4, get_info_v3
        from wxManager.decrypt.decrypt_dat import get_decode_code_v4
        from wxManager.decrypt import decrypt_v4, decrypt_v3

        # 尝试微信 4.x
        self.log('检测微信 4.x 进程...')
        wx_infos = get_info_v4()

        # 尝试微信 3.x
        if not wx_infos:
            self.log('未检测到微信 4.x，尝试微信 3.x...')
            version_list_path = os.path.join(_base, 'wxManager', 'decrypt', 'version_list.json')
            if os.path.exists(version_list_path):
                with open(version_list_path, 'r', encoding='utf-8') as f:
                    version_list = json.load(f)
                wx_infos = get_info_v3(version_list)

        if not wx_infos:
            self.log('未检测到正在运行的微信！请确保微信已登录且正在运行。')
            self.finished_signal.emit(False, '')
            return

        self.progress_signal.emit(10)
        all_output_dirs = []

        for idx, wx_info in enumerate(wx_infos):
            self.log(f'\n{"=" * 50}')
            self.log(f'账号 {idx + 1}: {wx_info.nick_name} ({wx_info.wxid})')
            self.log(f'版本: {wx_info.version}')
            self.log(f'目录: {wx_info.wx_dir}')

            if not wx_info.key:
                self.log('错误：未找到密钥，请重启微信后再试')
                continue

            # 判断是 4.x 还是 3.x
            is_v4 = hasattr(wx_info, 'raw_keys') and wx_info.raw_keys
            db_version = 4 if is_v4 or (wx_info.key and wx_info.key.startswith('raw:')) else 3

            me = Me()
            me.wx_dir = wx_info.wx_dir
            me.wxid = wx_info.wxid
            me.name = wx_info.nick_name

            output_dir = wx_info.wxid

            # ========== 第2步：解密数据库 ==========
            self.status_signal.emit(f'正在解密 {wx_info.nick_name} 的数据库...')

            if db_version == 4:
                me.xor_key = get_decode_code_v4(wx_info.wx_dir)
                info_data = me.to_json()
                raw_keys = wx_info.raw_keys if hasattr(wx_info, 'raw_keys') else None
                self.log(f'XOR密钥: 0x{me.xor_key:x}')
                self.log(f'开始解密数据库（微信4.x）...')
                decrypt_v4.decrypt_db_files(
                    wx_info.key, src_dir=wx_info.wx_dir,
                    dest_dir=output_dir, raw_keys=raw_keys
                )
                db_sub_dir = 'db_storage'
            else:
                info_data = me.to_json()
                self.log(f'开始解密数据库（微信3.x）...')
                decrypt_v3.decrypt_db_files(
                    wx_info.key, src_dir=wx_info.wx_dir,
                    dest_dir=output_dir
                )
                db_sub_dir = 'Msg'

            # 保存 info.json
            info_path = os.path.join(output_dir, db_sub_dir, 'info.json')
            os.makedirs(os.path.dirname(info_path), exist_ok=True)
            with open(info_path, 'w', encoding='utf-8') as f:
                json.dump(info_data, f, ensure_ascii=False, indent=4)

            self.log('数据库解密完成！')
            self.progress_signal.emit(40)

            # ========== 第3步：导出聊天记录 ==========
            self.status_signal.emit(f'正在导出 {wx_info.nick_name} 的聊天记录...')

            from wxManager import DatabaseConnection
            from exporter import HtmlExporter
            from exporter.config import FileType

            db_dir = os.path.join(output_dir, db_sub_dir)
            export_dir = os.path.join(output_dir, 'export_html')

            # 重新加载 Me 配置
            me2 = Me()
            me2.load_from_json(info_path)

            conn = DatabaseConnection(db_dir, db_version)
            database = conn.get_interface()
            if not database:
                self.log('数据库初始化失败！请检查路径或数据库版本')
                continue

            contacts = database.get_contacts()
            total = len(contacts)
            success = 0
            fail = 0
            skip = 0

            for i, contact in enumerate(contacts):
                # 跳过已导出的联系人
                contact_dir = os.path.join(
                    export_dir, '聊天记录',
                    f'{contact.remark}({contact.wxid})'
                )
                html_file = os.path.join(contact_dir, f'{contact.remark}.html')
                if os.path.exists(html_file):
                    skip += 1
                    continue

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

                # 每50个联系人报告一次
                if (i + 1) % 50 == 0:
                    self.log(f'  进度: {i + 1}/{total}')

            self.log(f'\n导出完成！成功: {success}  失败: {fail}  跳过: {skip}  总计: {total}')
            self.log(f'输出目录: {os.path.abspath(export_dir)}')
            all_output_dirs.append(os.path.abspath(export_dir))

        self.progress_signal.emit(100)
        self.status_signal.emit('全部完成！')
        output = all_output_dirs[0] if all_output_dirs else ''
        self.finished_signal.emit(True, output)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.output_dir = ''
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('WeChatMsg - 微信聊天记录导出工具')
        self.setMinimumSize(600, 500)
        self.resize(700, 550)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        # 标题
        title = QLabel('微信聊天记录导出工具')
        title.setFont(QFont('Microsoft YaHei', 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel('支持微信 3.x / 4.0 / 4.1（一键解密 + 导出 HTML）')
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet('color: #666;')
        layout.addWidget(subtitle)

        # 状态
        self.status_label = QLabel('请确保微信已登录且正在运行，然后点击下方按钮')
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setFont(QFont('Microsoft YaHei', 11))
        self.status_label.setStyleSheet('color: #333; padding: 8px;')
        layout.addWidget(self.status_label)

        # 开始按钮
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
        self.start_button.clicked.connect(self.on_start)
        layout.addWidget(self.start_button)

        # 进度条
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

        # 日志区域
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

        # 打开目录按钮（初始隐藏）
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
        self.open_dir_button.clicked.connect(self.on_open_dir)
        self.open_dir_button.setVisible(False)
        layout.addWidget(self.open_dir_button)

    def on_start(self):
        self.start_button.setEnabled(False)
        self.start_button.setText('正在运行...')
        self.open_dir_button.setVisible(False)
        self.progress_bar.setValue(0)
        self.log_text.clear()

        self.worker = WorkerThread()
        self.worker.log_signal.connect(self.append_log)
        self.worker.progress_signal.connect(self.progress_bar.setValue)
        self.worker.status_signal.connect(self.status_label.setText)
        self.worker.finished_signal.connect(self.on_finished)
        self.worker.start()

    def append_log(self, text):
        self.log_text.appendPlainText(text)

    def on_finished(self, success, output_dir):
        self.start_button.setEnabled(True)
        self.start_button.setText('一键开始')

        if success:
            self.status_label.setText('全部完成！')
            self.status_label.setStyleSheet('color: #07C160; padding: 8px; font-weight: bold;')
            if output_dir:
                self.output_dir = output_dir
                self.open_dir_button.setVisible(True)
        else:
            self.status_label.setText('运行出错，请查看日志')
            self.status_label.setStyleSheet('color: #ff4d4f; padding: 8px; font-weight: bold;')

    def on_open_dir(self):
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
