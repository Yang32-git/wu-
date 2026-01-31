"""
日志记录模块
提供统一的日志记录功能
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from datetime import datetime


def setup_logger(name='recon-tool', verbose=False, log_file=None):
    """
    设置日志记录器
    
    Args:
        name: 日志记录器名称
        verbose: 是否启用详细输出
        log_file: 日志文件路径
    
    Returns:
        logging.Logger: 配置好的日志记录器
    """
    # 创建日志记录器
    logger = logging.getLogger(name)
    
    # 如果记录器已经有处理器，返回它（避免重复配置）
    if logger.handlers:
        return logger
    
    # 设置日志级别
    log_level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(log_level)
    
    # 创建日志格式
    formatter = logging.Formatter(
        fmt='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # 控制台处理器
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 文件处理器（如果指定了日志文件）
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 使用RotatingFileHandler避免日志文件过大
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)  # 文件记录所有级别
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name=None):
    """
    获取日志记录器
    
    Args:
        name: 日志记录器名称，如果为None则返回根记录器
    
    Returns:
        logging.Logger: 日志记录器
    """
    if name:
        return logging.getLogger(name)
    return logging.getLogger('recon-tool')


class ColoredLogger:
    """
    带颜色的日志输出（可选）
    """
    
    COLORS = {
        'DEBUG': '\033[36m',    # 青色
        'INFO': '\033[32m',     # 绿色
        'WARNING': '\033[33m',  # 黄色
        'ERROR': '\033[31m',    # 红色
        'CRITICAL': '\033[35m', # 紫色
    }
    RESET = '\033[0m'
    
    @classmethod
    def setup_colored_logger(cls, name='recon-tool', verbose=False):
        """设置带颜色的日志记录器"""
        logger = logging.getLogger(name)
        
        if logger.handlers:
            return logger
        
        log_level = logging.DEBUG if verbose else logging.INFO
        logger.setLevel(log_level)
        
        # 创建带颜色的格式
        class ColoredFormatter(logging.Formatter):
            def format(self, record):
                color = cls.COLORS.get(record.levelname, '')
                record.levelname = f"{color}{record.levelname}{cls.RESET}"
                return super().format(record)
        
        formatter = ColoredFormatter(
            fmt='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        return logger


# 进度条相关函数
def print_progress(current, total, prefix="", suffix="", length=50):
    """
    打印进度条
    
    Args:
        current: 当前进度
        total: 总进度
        prefix: 前缀文本
        suffix: 后缀文本
        length: 进度条长度
    """
    percent = (current / total) * 100
    filled_length = int(length * current // total)
    bar = '█' * filled_length + '-' * (length - filled_length)
    
    sys.stdout.write(f'\r{prefix} |{bar}| {percent:.1f}% {suffix}')
    sys.stdout.flush()
    
    if current == total:
        sys.stdout.write('\n')
        sys.stdout.flush()
