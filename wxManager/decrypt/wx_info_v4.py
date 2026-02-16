#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Time        : 2025/1/10 2:36
@Author      : SiYuan
@Email       : 863909694@qq.com
@File        : wxManager-wx_info_v4.py
@Description : 部分思路参考：https://github.com/0xlane/wechat-dump-rs
"""

import ctypes
import multiprocessing
import os
import os.path
import hmac
import struct
import time
from ctypes import wintypes
from multiprocessing import freeze_support

import pymem
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import yara

from wxManager.decrypt.common import WeChatInfo
from wxManager.decrypt.common import get_version

# 定义必要的常量
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000

# SQLCipher 4 参数
IV_SIZE = 16
HMAC_SHA512_SIZE = 64
KEY_SIZE = 32
AES_BLOCK_SIZE = 16
ROUND_COUNT = 256000
PAGE_SIZE = 4096
SALT_SIZE = 16

# Windows API Constants
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


# 定义 MEMORY_BASIC_INFORMATION 结构
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


# 初始化 Windows API
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t,
                              ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL


# 打开目标进程
def open_process(pid):
    return kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)


def read_process_memory(process_handle, address, size):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    success = kernel32.ReadProcessMemory(
        process_handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read)
    )
    if not success:
        return None
    return buffer.raw


def get_memory_regions(process_handle):
    regions = []
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    while kernel32.VirtualQueryEx(
            process_handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi)
    ):
        if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE:
            regions.append((mbi.BaseAddress, mbi.RegionSize))
        address += mbi.RegionSize
    return regions


def get_all_memory_regions(process_handle):
    """获取所有已提交的内存区域（不限MEM_PRIVATE），用于codec_ctx搜索"""
    regions = []
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    while kernel32.VirtualQueryEx(
            process_handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi)
    ):
        if mbi.State == MEM_COMMIT:
            regions.append((mbi.BaseAddress, mbi.RegionSize))
        address += mbi.RegionSize
    return regions


def read_string(data: bytes, offset, size):
    try:
        return data[offset:offset + size].decode('utf-8')
    except (UnicodeDecodeError, IndexError):
        return ''


def read_num(data: bytes, offset, size):
    # 构建格式字符串，根据 size 来选择相应的格式
    if size == 1:
        fmt = '<B'  # 1 字节，unsigned char
    elif size == 2:
        fmt = '<H'  # 2 字节，unsigned short
    elif size == 4:
        fmt = '<I'  # 4 字节，unsigned int
    elif size == 8:
        fmt = '<Q'  # 8 字节，unsigned long long
    else:
        raise ValueError("Unsupported size")

    # 使用 struct.unpack 从指定 offset 开始读取 size 字节的数据并转换为数字
    result = struct.unpack_from(fmt, data, offset)[0]  # 通过 unpack_from 来读取指定偏移的数据
    return result


def read_bytes(data: bytes, offset, size):
    return data[offset:offset + size]


def read_bytes_from_pid(pid: int, addr: int, size: int):
    hprocess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not hprocess:
        return b''
    try:
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        success = ReadProcessMemory(hprocess, addr, buffer, size, ctypes.byref(bytes_read))
        if not success:
            CloseHandle(hprocess)
            return b''
        CloseHandle(hprocess)
        return bytes(buffer)
    except Exception:
        CloseHandle(hprocess)
        return b''


def read_string_from_pid(pid: int, addr: int, size: int):
    bytes0 = read_bytes_from_pid(pid, addr, size)
    try:
        return bytes0.decode('utf-8')
    except:
        return ''


def _verify_hmac(derived_key, buf):
    """用推导后的密钥验证数据库页HMAC"""
    salt = buf[:SALT_SIZE]
    mac_salt = bytes(x ^ 0x3a for x in salt)
    mac_key = PBKDF2(derived_key, mac_salt, dkLen=KEY_SIZE, count=2, hmac_hash_module=SHA512)
    reserve = IV_SIZE + HMAC_SHA512_SIZE
    reserve = ((reserve + AES_BLOCK_SIZE - 1) // AES_BLOCK_SIZE) * AES_BLOCK_SIZE
    start = SALT_SIZE
    end = PAGE_SIZE
    mac = hmac.new(mac_key, buf[start:end - reserve + IV_SIZE], SHA512)
    mac.update(struct.pack('<I', 1))
    hash_mac = mac.digest()
    hash_mac_start_offset = end - reserve + IV_SIZE
    hash_mac_end_offset = hash_mac_start_offset + len(hash_mac)
    return hash_mac == buf[hash_mac_start_offset:hash_mac_end_offset]


def is_ok(passphrase, buf):
    """验证passphrase：先通过PBKDF2推导密钥，再验证HMAC"""
    salt = buf[:SALT_SIZE]
    derived_key = PBKDF2(passphrase, salt, dkLen=KEY_SIZE, count=ROUND_COUNT, hmac_hash_module=SHA512)
    return _verify_hmac(derived_key, buf)


def is_ok_raw(raw_key, buf):
    """验证原始AES密钥：跳过PBKDF2推导，直接验证HMAC（极快）"""
    return _verify_hmac(raw_key, buf)


def check_chunk(chunk, buf):
    if is_ok(chunk, buf):
        return chunk
    return False


def get_key_(keys, buf):
    # 第一阶段：raw key验证（极快）
    for key in keys:
        if is_ok_raw(key, buf):
            return bytes.hex(key)

    # 第二阶段：PBKDF2验证（慢，并行）
    pool = multiprocessing.Pool(processes=max(1, multiprocessing.cpu_count() // 2))
    results = pool.starmap(check_chunk, ((key, buf) for key in keys))
    pool.close()
    pool.join()

    for r in results:
        if r:
            return bytes.hex(r)
    return None


def get_key_inner(pid, process_infos):
    """
    扫描可能为key的内存（原始YARA方法）
    :param pid:
    :param process_infos:
    :return:
    """
    process_handle = open_process(pid)
    # 扩展YARA规则：匹配MSVC std::string堆分配结构
    # 结构: [8字节指针][8字节填充][8字节长度=32][8字节容量]
    rules_v4_key = r'''
        rule GetKeyAddrStub
        {
            strings:
                $a = /.{6}\x00{2}\x00{8}\x20\x00{7}\x2f\x00{7}/
                $b = /.{6}\x00{2}\x00{8}\x20\x00{7}\x3f\x00{7}/
                $c = /.{6}\x00{2}\x00{8}\x20\x00{7}[\x20-\x7f]\x00{7}/
                $d = /.{6}\x00{2}.{8}\x20\x00{7}[\x20-\x7f]\x00{7}/
            condition:
                any of them
        }
        '''
    rules = yara.compile(source=rules_v4_key)
    pre_addresses = []
    for base_address, region_size in process_infos:
        memory = read_process_memory(process_handle, base_address, region_size)
        if not memory:
            continue
        matches = rules.match(data=memory)
        if matches:
            for match in matches:
                if match.rule == 'GetKeyAddrStub':
                    for string in match.strings:
                        for instance in string.instances:
                            offset, content = instance.offset, instance.matched_data
                            addr = read_num(memory, offset, 8)
                            pre_addresses.append(addr)
    keys = []
    key_set = set()
    for pre_address in pre_addresses:
        key = read_bytes_from_pid(pid, pre_address, 32)
        if key and key not in key_set:
            keys.append(key)
            key_set.add(key)
    return keys


def get_key_by_phone_type(pm, pid, db_buf):
    """
    策略2: 通过phone_type字符串搜索密钥
    在Weixin.dll中搜索iphone/android/ipad字符串，在其附近搜索密钥指针
    注意：此方法在PC版微信中命中率较低，主要作为备用策略
    """
    phone_types = [b'iphone\x00', b'android\x00', b'ipad\x00']

    weixin_dll = None
    for m in pm.list_modules():
        if 'weixin.dll' in m.name.lower():
            weixin_dll = m
            break

    if not weixin_dll:
        return None

    for phone_type in phone_types:
        try:
            addrs = pm.pattern_scan_module(phone_type, weixin_dll, return_multiple=True)
        except Exception:
            continue

        if addrs and len(addrs) >= 2:
            for addr in addrs[::-1]:
                for offset in range(0, 2000, 8):
                    key_addr_ptr = addr - offset
                    try:
                        addr_bytes = read_bytes_from_pid(pid, key_addr_ptr, 8)
                        if not addr_bytes or len(addr_bytes) != 8:
                            continue
                        key_addr = int.from_bytes(addr_bytes, 'little')

                        if 0x10000 < key_addr < 0x7FFFFFFFFFFF:
                            key = read_bytes_from_pid(pid, key_addr, 32)
                            if key and len(key) == 32:
                                unique = len(set(key))
                                zeros = key.count(0)
                                if unique >= 20 and zeros <= 4:
                                    if is_ok_raw(key, db_buf) or is_ok(key, db_buf):
                                        return key.hex()
                    except Exception:
                        continue
    return None


def get_key_by_entropy_scan(pid, process_handle, db_buf):
    """
    策略3: 在私有内存中搜索长度标记模式（0x20=32），读取关联指针指向的32字节数据作为密钥候选
    """
    candidates = set()
    regions = get_memory_regions(process_handle)
    # 模式A: 8字节零+长度32（原始模式）
    pattern_a = b'\x00' * 8 + b'\x20' + b'\x00' * 7
    # 模式B: 仅长度32（更灵活，不要求前面8字节为0）
    pattern_b = b'\x20' + b'\x00' * 7

    for base_addr, size in regions:
        memory = read_process_memory(process_handle, base_addr, size)
        if not memory:
            continue

        # 模式A扫描
        pos = 0
        while True:
            pos = memory.find(pattern_a, pos)
            if pos == -1:
                break
            if pos >= 8:
                addr = int.from_bytes(memory[pos-8:pos], 'little')
                if 0x10000 < addr < 0x7FFFFFFFFFFF:
                    key = read_bytes_from_pid(pid, addr, 32)
                    if key and len(key) == 32:
                        unique = len(set(key))
                        zeros = key.count(0)
                        if unique >= 20 and zeros <= 4:
                            candidates.add(key)
            pos += 1

        # 模式B扫描：跳过8字节任意填充读取指针
        pos = 0
        while True:
            pos = memory.find(pattern_b, pos)
            if pos == -1:
                break
            # 检查后续8字节是否为合理的capacity值（32-4095）
            if pos + 8 <= len(memory) - 8:
                capacity = int.from_bytes(memory[pos+8:pos+16], 'little')
                if 32 <= capacity < 4096 and pos >= 16:
                    addr = int.from_bytes(memory[pos-16:pos-8], 'little')
                    if 0x10000 < addr < 0x7FFFFFFFFFFF:
                        key = read_bytes_from_pid(pid, addr, 32)
                        if key and len(key) == 32:
                            unique = len(set(key))
                            zeros = key.count(0)
                            if unique >= 20 and zeros <= 4:
                                candidates.add(key)
            pos += 1

    for key in candidates:
        if is_ok_raw(key, db_buf):
            return key.hex()
    for key in candidates:
        if is_ok(key, db_buf):
            return key.hex()

    return None


def _is_valid_key_candidate(key):
    """检查32字节是否可能是密钥"""
    if not key or len(key) != 32:
        return False
    return len(set(key)) >= 20 and key.count(0) <= 4


def get_key_by_db_key_string(pid, process_handle, db_buf):
    """
    策略4: 搜索 DB_KEY_STING 字符串（WeChat内部密钥标识符，原始拼写如此）
    在标记附近查找指向密钥数据的指针
    """
    regions = get_memory_regions(process_handle)
    marker = b'DB_KEY_STING'
    candidates = set()

    for base_addr, size in regions:
        memory = read_process_memory(process_handle, base_addr, size)
        if not memory:
            continue

        pos = 0
        while True:
            pos = memory.find(marker, pos)
            if pos == -1:
                break

            # 在DB_KEY_STING前后512字节范围内查找指针
            search_start = max(0, pos - 512)
            search_end = min(len(memory), pos + 512)

            for offset in range(search_start, search_end - 8, 8):
                addr = int.from_bytes(memory[offset:offset + 8], 'little')
                if 0x10000 < addr < 0x7FFFFFFFFFFF:
                    key = read_bytes_from_pid(pid, addr, 32)
                    if _is_valid_key_candidate(key):
                        candidates.add(key)
            pos += len(marker)

    for key in candidates:
        if is_ok_raw(key, db_buf):
            return key.hex()
    for key in candidates:
        if is_ok(key, db_buf):
            return key.hex()

    return None


def get_raw_keys_from_codec_ctx(pid, process_handle, wx_dir):
    """
    策略5: 通过SQLCipher codec_ctx结构体提取per-DB raw key
    微信4.1+使用raw key模式，每个数据库有独立的派生密钥。
    方法：搜索kdf_iter=256000模式 → 检查+68处的salt指针 → 跟随+100处跳转到cipher_ctx → 读取+8处的密钥
    """
    db_dir = os.path.join(wx_dir, 'db_storage')
    if not os.path.exists(db_dir):
        return None

    # 收集所有加密DB的salt → 首页数据
    db_salts = {}  # salt_hex -> first_page_bytes
    salt_set = set()
    for root, dirs, files in os.walk(db_dir):
        for f in files:
            if f.endswith('.db'):
                fp = os.path.join(root, f)
                sz = os.path.getsize(fp)
                if sz >= PAGE_SIZE:
                    with open(fp, 'rb') as fh:
                        header = fh.read(PAGE_SIZE)
                    if header[:15] != b'SQLite format 3':
                        salt_hex = header[:SALT_SIZE].hex()
                        db_salts[salt_hex] = header
                        salt_set.add(salt_hex)

    if not db_salts:
        return None

    # 计算所有hmac_salt (salt XOR 0x3a) 用于排除
    hmac_salt_set = set()
    for salt_hex in salt_set:
        salt_bytes = bytes.fromhex(salt_hex)
        hmac_salt_set.add(bytes(x ^ 0x3a for x in salt_bytes).hex())

    regions = get_all_memory_regions(process_handle)
    kdf_pattern = struct.pack('<II', ROUND_COUNT, 2)  # kdf_iter=256000, fast_kdf_iter=2
    raw_keys = {}  # salt_hex -> raw_key_hex

    for base, size in regions:
        mem = read_process_memory(process_handle, base, size)
        if not mem:
            continue
        pos = 0
        while True:
            pos = mem.find(kdf_pattern, pos)
            if pos == -1:
                break

            # 检查+68是否指向某个DB的salt（标识codec_ctx）
            if pos + 76 <= len(mem):
                ptr68 = struct.unpack_from('<Q', mem, pos + 68)[0]
                if 0x10000 < ptr68 < 0x7FFFFFFFFFFF:
                    salt_data = read_bytes_from_pid(pid, ptr68, SALT_SIZE)
                    if salt_data:
                        salt_hex = salt_data.hex()
                        if salt_hex in salt_set and salt_hex not in raw_keys:
                            # 找到codec_ctx，跟随指针找cipher_ctx中的密钥
                            # codec_ctx+92到+112范围内寻找指向cipher_ctx的指针
                            for codec_off in [92, 96, 100, 104, 108, 112]:
                                ptr_pos = pos + codec_off
                                if ptr_pos + 8 > len(mem):
                                    continue
                                ptr1 = struct.unpack_from('<Q', mem, ptr_pos)[0]
                                if not (0x10000 < ptr1 < 0x7FFFFFFFFFFF):
                                    continue
                                ctx = read_bytes_from_pid(pid, ptr1, 128)
                                if not ctx or len(ctx) < 24:
                                    continue
                                # 在cipher_ctx中搜索密钥指针（通常在+8位置）
                                for ctx_off in range(0, min(64, len(ctx) - 8), 8):
                                    ptr2 = struct.unpack_from('<Q', ctx, ctx_off)[0]
                                    if not (0x10000 < ptr2 < 0x7FFFFFFFFFFF):
                                        continue
                                    key_data = read_bytes_from_pid(pid, ptr2, KEY_SIZE)
                                    if not key_data or len(key_data) != KEY_SIZE:
                                        continue
                                    # 排除salt和hmac_salt
                                    key_hex_16 = key_data[:SALT_SIZE].hex()
                                    if key_hex_16 in salt_set or key_hex_16 in hmac_salt_set:
                                        continue
                                    if len(set(key_data)) < 20:
                                        continue
                                    # 验证raw key
                                    if is_ok_raw(key_data, db_salts[salt_hex]):
                                        raw_keys[salt_hex] = key_data.hex()
                                        break
                                if salt_hex in raw_keys:
                                    break
            pos += 1

    return raw_keys if raw_keys else None


def get_key(pid, process_handle, buf):
    """
    获取数据库密钥 - 多策略搜索
    策略1: YARA规则匹配std::string结构
    策略2: phone_type字符串搜索（Weixin.dll模块）
    策略3: 长度标记模式扫描（灵活模式）
    策略4: DB_KEY_STING标识符搜索
    """
    process_infos = get_memory_regions(process_handle)

    def split_list(lst, n):
        k, m = divmod(len(lst), n)
        return (lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))

    # 策略1: YARA规则方法（扩展模式）
    keys = []
    pool = multiprocessing.Pool(processes=multiprocessing.cpu_count() // 2)
    results = pool.starmap(get_key_inner, ((pid, process_info_) for process_info_ in
                                           split_list(process_infos, min(len(process_infos), 40))))
    pool.close()
    pool.join()
    for r in results:
        if r:
            keys += r
    key = get_key_(keys, buf)
    if key:
        return key

    # 策略2: phone_type字符串搜索
    try:
        pm = pymem.Pymem('Weixin.exe')
        key = get_key_by_phone_type(pm, pid, buf)
        if key:
            return key
    except Exception:
        pass

    # 策略3: 灵活模式扫描
    key = get_key_by_entropy_scan(pid, process_handle, buf)
    if key:
        return key

    # 策略4: DB_KEY_STING标识符搜索
    key = get_key_by_db_key_string(pid, process_handle, buf)
    if key:
        return key

    return None


def get_wx_dir(process_handle):
    rules_v4_dir = r'''
    rule GetDataDir {
        strings:
            $a = /[a-zA-Z]:\\(.{1,100}?\\){0,1}?xwechat_files\\[0-9a-zA-Z_-]{6,24}?\\db_storage\\/
        condition:
            $a
    }
    '''
    rules = yara.compile(source=rules_v4_dir)
    process_infos = get_memory_regions(process_handle)
    wx_dir_cnt = {}
    for base_address, region_size in process_infos:
        memory = read_process_memory(process_handle, base_address, region_size)
        if not memory:
            continue
        if b'db_storage' not in memory:
            continue
        matches = rules.match(data=memory)
        if matches:
            for match in matches:
                if match.rule == 'GetDataDir':
                    for string in match.strings:
                        content = string.instances[0].matched_data
                        wx_dir_cnt[content] = wx_dir_cnt.get(content, 0) + 1
    return max(wx_dir_cnt, key=wx_dir_cnt.get).decode('utf-8') if wx_dir_cnt else ''


def get_nickname(pid):
    process_handle = open_process(pid)
    if not process_handle:
        print(f"无法打开进程 {pid}")
        return {}
    process_infos = get_memory_regions(process_handle)
    rules_v4_phone = r'''
    rule GetPhoneNumberOffset {
        strings:
            $a = /[\x01-\x20]\x00{7}(\x0f|\x1f)\x00{7}[0-9]{11}\x00{5}\x0b\x00{7}\x0f\x00{7}/
        condition:
            $a
    }
    '''
    nick_name = ''
    phone = ''
    account_name = ''
    rules = yara.compile(source=rules_v4_phone)
    for base_address, region_size in process_infos:
        memory = read_process_memory(process_handle, base_address, region_size)
        if not memory:
            continue
        matches = rules.match(data=memory)
        if matches:
            for match in matches:
                if match.rule == 'GetPhoneNumberOffset':
                    for string in match.strings:
                        instance = string.instances[0]
                        offset, content = instance.offset, instance.matched_data
                        phone_addr = offset + 0x10
                        phone = read_string(memory, phone_addr, 11)

                        data_slice = memory[offset:offset + 8]
                        nick_name_length = struct.unpack('<Q', data_slice)[0]
                        nick_name = read_string(memory, phone_addr - 0x20, nick_name_length)
                        account_name_length = read_num(memory, phone_addr - 0x30, 8)
                        account_name = read_string(memory, phone_addr - 0x40, account_name_length)
                        if not account_name:
                            addr = read_num(memory, phone_addr - 0x40, 8)
                            account_name = read_string_from_pid(pid, addr, account_name_length)
    return {
        'nick_name': nick_name,
        'phone': phone,
        'account_name': account_name
    }


def worker(pid, queue):
    nickname_dic = get_nickname(pid)
    queue.put(nickname_dic)


def dump_wechat_info_v4(pid) -> WeChatInfo | None:
    wechat_info = WeChatInfo()
    wechat_info.pid = pid
    wechat_info.version = get_version(pid)
    process_handle = open_process(pid)
    if not process_handle:
        print(f"无法打开进程 {pid}")
        return wechat_info
    queue = multiprocessing.Queue()
    process = multiprocessing.Process(target=worker, args=(pid, queue))

    process.start()

    wechat_info.wx_dir = get_wx_dir(process_handle)
    if not wechat_info.wx_dir:
        return wechat_info

    # 策略1（快）: 通过codec_ctx提取per-DB raw key（微信4.1+，约2秒）
    wx_dir_parent = '\\'.join(wechat_info.wx_dir.rstrip('\\').split('\\')[:-1])
    raw_keys = get_raw_keys_from_codec_ctx(pid, process_handle, wx_dir_parent)
    if raw_keys:
        wechat_info.raw_keys = raw_keys
        wechat_info.key = f'raw:{len(raw_keys)}'
    else:
        # 策略2（慢）: YARA多策略搜索单密钥（微信4.0.x）
        db_file_path = os.path.join(wechat_info.wx_dir, 'favorite', 'favorite_fts.db')
        if not os.path.exists(db_file_path):
            db_file_path = os.path.join(wechat_info.wx_dir, 'head_image', 'head_image.db')
        with open(db_file_path, 'rb') as f:
            buf = f.read()
        wechat_info.key = get_key(pid, process_handle, buf)

    ctypes.windll.kernel32.CloseHandle(process_handle)
    wechat_info.wxid = '_'.join(wechat_info.wx_dir.split('\\')[-3].split('_')[0:-1])
    wechat_info.wx_dir = '\\'.join(wechat_info.wx_dir.split('\\')[:-2])
    process.join()  # 等待子进程完成
    if not queue.empty():
        nickname_info = queue.get()
        wechat_info.nick_name = nickname_info.get('nick_name', '')
        wechat_info.phone = nickname_info.get('phone', '')
        wechat_info.account_name = nickname_info.get('account_name', '')
    if not wechat_info.key:
        wechat_info.errcode = 404
    else:
        wechat_info.errcode = 200
    return wechat_info


if __name__ == '__main__':
    freeze_support()
    st = time.time()
    pm = pymem.Pymem("Weixin.exe")
    pid = pm.process_id
    w = dump_wechat_info_v4(pid)
    print(w)
    et = time.time()
    print(et - st)
