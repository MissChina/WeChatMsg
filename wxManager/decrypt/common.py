#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Time        : 2025/3/7 16:39 
@Author      : SiYuan 
@Email       : 863909694@qq.com 
@File        : MemoTrace-common.py 
@Description : 
"""
import psutil
import win32api

if __name__ == '__main__':
    pass


def get_version(pid):
    p = psutil.Process(pid)
    version_info = win32api.GetFileVersionInfo(p.exe(), '\\')
    version = f"{win32api.HIWORD(version_info['FileVersionMS'])}.{win32api.LOWORD(version_info['FileVersionMS'])}.{win32api.HIWORD(version_info['FileVersionLS'])}.{win32api.LOWORD(version_info['FileVersionLS'])}"
    return version


class WeChatInfo:
    def __init__(self):
        self.pid = 0
        self.version = '0.0.0.0'
        self.account_name = ''
        self.nick_name = ''
        self.phone = ''
        self.wx_dir = ''
        self.key = ''
        self.raw_keys = None  # dict: {salt_hex: raw_key_hex} 微信4.1+ per-DB raw key
        self.wxid = ''
        self.errcode: int = 404  # 405: 版本不匹配, 404: 重新登录微信, other: 未知错误
        self.errmsg: str = '错误！请登录微信。'

    def __str__(self):
        raw_keys_info = f'{len(self.raw_keys)} DBs' if self.raw_keys else 'None'
        return f'''
pid:          {self.pid}
version:      {self.version}
account_name: {self.account_name}
nickname:     {self.nick_name}
phone:        {self.phone}
wxid:         {self.wxid}
wx_dir:       {self.wx_dir}
key:          {self.key}
raw_keys:     {raw_keys_info}
'''

    def to_json(self):
        return {
            'version': self.version,
            'nickname': self.nick_name,
            'wx_dir': self.wx_dir,
            'wxid': self.wxid
        }