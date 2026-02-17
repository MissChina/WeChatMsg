import logging
import os
import sys
import time
import traceback
from functools import wraps

filename = time.strftime("%Y-%m-%d", time.localtime(time.time()))
logger = logging.getLogger('WeChatMsg')
logger.setLevel(level=logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')

# 日志文件路径：exe所在目录 或 项目根目录
if getattr(sys, 'frozen', False):
    log_dir = os.path.dirname(sys.executable)
else:
    log_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
log_file = os.path.join(log_dir, f'WeChatMsg-{filename}.log')

file_handler = logging.FileHandler(log_file, encoding='utf-8')
file_handler.setLevel(level=logging.INFO)
file_handler.setFormatter(formatter)
stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.DEBUG)
stream_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(stream_handler)


def log(func):
    @wraps(func)
    def log_(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(
                f"\n{func.__qualname__} is error,params:{(args, kwargs)},here are details:\n{traceback.format_exc()}")
    return log_
