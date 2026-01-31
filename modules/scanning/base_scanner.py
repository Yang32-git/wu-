"""
基础扫描器类
所有扫描器都应继承此类
"""

from abc import ABC, abstractmethod
from modules.utils.logger import get_logger


class BaseScanner(ABC):
    """扫描器基类"""
    
    def __init__(self, config, logger=None):
        """
        初始化扫描器
        
        Args:
            config: 配置字典
            logger: 日志记录器
        """
        self.config = config
        self.logger = logger or get_logger()
        self.results = {}
        self.description = "基础扫描器"
        self.version = "1.0"
        self.author = "安全团队"
    
    @abstractmethod
    def scan(self, target, timeout=None, wordlist=None):
        """
        执行扫描
        
        Args:
            target: 扫描目标
            timeout: 超时时间
            wordlist: 字典文件
        
        Returns:
            dict: 扫描结果
        """
        pass
    
    def is_valid_target(self, target):
        """
        验证目标是否有效
        
        Args:
            target: 目标字符串
        
        Returns:
            bool: 是否有效
        """
        if not target or not isinstance(target, str):
            return False
        return len(target.strip()) > 0
    
    def format_result(self, success, data=None, error=None):
        """
        格式化扫描结果
        
        Args:
            success: 是否成功
            data: 扫描数据
            error: 错误信息
        
        Returns:
            dict: 格式化后的结果
        """
        return {
            'success': success,
            'data': data or {},
            'error': error,
            'scanner': self.__class__.__name__
        }
    
    def log_info(self, message):
        """记录信息日志"""
        self.logger.info(f"[{self.__class__.__name__}] {message}")
    
    def log_warning(self, message):
        """记录警告日志"""
        self.logger.warning(f"[{self.__class__.__name__}] {message}")
    
    def log_error(self, message):
        """记录错误日志"""
        self.logger.error(f"[{self.__class__.__name__}] {message}")
    
    def log_debug(self, message):
        """记录调试日志"""
        self.logger.debug(f"[{self.__class__.__name__}] {message}")


class ScannerException(Exception):
    """扫描器异常类"""
    pass
