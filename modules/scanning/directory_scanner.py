"""
网站目录扫描器
扫描网站的目录和文件
"""

import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.scanning.base_scanner import BaseScanner

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DirectoryScanner(BaseScanner):
    """目录扫描器"""
    
    def __init__(self, config, logger=None):
        super().__init__(config, logger)
        self.description = "网站目录扫描器"
        
        # 常用目录字典
        self.common_dirs = [
            'admin', 'administrator', 'webadmin', 'wp-admin', 'dashboard', 'control', 'panel',
            'backend', 'manage', 'management', 'login', 'signin', 'register', 'signup',
            'config', 'configuration', 'conf', 'settings', 'setup', 'install', 'installer',
            'backup', 'backups', 'old', 'old_site', 'old_site_backup', 'archive', 'archives',
            'db', 'database', 'sql', 'data', 'dump', 'dumps', 'logs', 'log', 'tmp', 'temp',
            'test', 'testing', 'dev', 'development', 'staging', 'demo', 'demos',
            'api', 'apis', 'rest', 'restapi', 'v1', 'v2', 'v3', 'webhook', 'webhooks',
            'css', 'js', 'javascript', 'images', 'img', 'upload', 'uploads', 'files', 'file',
            'media', 'assets', 'static', 'resources', 'resource', 'download', 'downloads',
            'docs', 'documents', 'document', 'doc', 'help', 'support', 'faq', 'faqs',
            'about', 'contact', 'info', 'information', 'news', 'blog', 'blogs', 'article',
            'articles', 'post', 'posts', 'forum', 'forums', 'board', 'boards', 'thread',
            'threads', 'topic', 'topics', 'category', 'categories', 'tag', 'tags',
            'user', 'users', 'member', 'members', 'profile', 'profiles', 'account',
            'accounts', 'auth', 'authentication', 'authorize', 'authorization', 'oauth',
            'phpmyadmin', 'pma', 'mysql', 'mysql-admin', 'dbadmin', 'database-admin',
            'webmail', 'mail', 'email', 'smtp', 'pop', 'imap', 'mailadmin',
            'stats', 'statistics', 'analytics', 'metrics', 'reports', 'report',
            'error', 'errors', '404', '403', '500', '503', 'maintenance', 'maint',
            'cgi-bin', 'bin', 'scripts', 'script', 'cgi', 'php', 'asp', 'aspx', 'jsp',
            'java', 'python', 'py', 'pl', 'perl', 'cgi-bin', 'server', 'servers',
            'status', 'monitor', 'monitoring', 'health', 'check', 'alive', 'ping',
            'version', 'versions', 'info', 'phpinfo', 'server-info', 'server-status',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
            '.git', '.git/config', '.git/HEAD', '.svn', '.svn/entries', 'CVS', 'CVS/Entries',
            '.env', '.env.local', '.env.prod', '.env.production', '.htaccess', '.htpasswd',
            'web.config', 'config.php', 'config.inc.php', 'configuration.php',
            'wp-config.php', 'wp-config.bak', 'wp-config.old', 'wp-config.php.bak',
            'config.bak', 'config.old', 'config.php.bak', 'config.php.old',
            'backup.zip', 'backup.tar', 'backup.tar.gz', 'backup.rar', 'backup.7z',
            'site.zip', 'site.tar', 'site.tar.gz', 'site.rar', 'site.7z',
            'www.zip', 'www.tar', 'www.tar.gz', 'www.rar', 'www.7z',
            'public.zip', 'public.tar', 'public.tar.gz', 'public.rar', 'public.7z',
            'html.zip', 'html.tar', 'html.tar.gz', 'html.rar', 'html.7z',
            'wwwroot.zip', 'wwwroot.tar', 'wwwroot.tar.gz', 'wwwroot.rar', 'wwwroot.7z'
        ]
        
        # 文件扩展名
        self.extensions = config.get('directory', {}).get('extensions', 
            ['.php', '.asp', '.aspx', '.jsp', '.html', '.js', '.txt', '.bak'])
        
        # 状态码
        self.status_codes = config.get('directory', {}).get('status_codes', 
            [200, 204, 301, 302, 307, 403, 401])
        
        # 请求头
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
    
    def scan(self, target, timeout=5, wordlist=None):
        """
        扫描网站目录
        
        Args:
            target: 目标网站URL
            timeout: 超时时间
            wordlist: 自定义字典文件
        
        Returns:
            dict: 扫描结果
        """
        if not self.is_valid_target(target):
            return self.format_result(False, error="无效的目标")
        
        # 确保URL格式正确
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # 移除末尾的斜杠
        target = target.rstrip('/')
        
        self.log_info(f"开始扫描目录: {target}")
        
        results = {
            'target': target,
            'directories': [],
            'files': [],
            'total_found': 0,
            'scan_stats': {
                'total_requests': 0,
                'successful_requests': 0,
                'failed_requests': 0
            }
        }
        
        try:
            # 获取字典列表
            dir_list = self._get_wordlist(wordlist) if wordlist else self.common_dirs
            
            # 首先检查目标是否可访问
            if not self._check_target_accessible(target, timeout):
                return self.format_result(False, error="目标网站无法访问")
            
            # 扫描目录
            directories = self._scan_directories(target, dir_list, timeout)
            results['directories'] = directories
            results['total_found'] += len(directories)
            
            # 扫描文件（在发现的目录中）
            if directories and self.config.get('directory', {}).get('scan_files', True):
                files = self._scan_files(target, directories, timeout)
                results['files'] = files
                results['total_found'] += len(files)
            
            # 更新统计信息
            results['scan_stats']['successful_requests'] = len(directories) + len(files)
            results['scan_stats']['total_requests'] = len(dir_list)
            
            self.log_info(f"目录扫描完成，发现 {results['total_found']} 个有效路径")
            
            return self.format_result(True, results)
            
        except Exception as e:
            self.log_error(f"目录扫描时出错: {str(e)}")
            return self.format_result(False, error=str(e))
    
    def _get_wordlist(self, wordlist_file):
        """
        从文件读取字典
        
        Args:
            wordlist_file: 字典文件路径
        
        Returns:
            list: 字典列表
        """
        try:
            with open(wordlist_file, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except:
            return self.common_dirs
    
    def _check_target_accessible(self, target, timeout):
        """
        检查目标是否可访问
        
        Args:
            target: 目标URL
            timeout: 超时时间
        
        Returns:
            bool: 是否可访问
        """
        try:
            response = requests.get(target, timeout=timeout, headers=self.headers, verify=False)
            return response.status_code < 500
        except:
            return False
    
    def _scan_directories(self, target, dir_list, timeout):
        """
        扫描目录
        
        Args:
            target: 目标URL
            dir_list: 目录列表
            timeout: 超时时间
        
        Returns:
            list: 发现的目录列表
        """
        directories = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_dir = {}
            
            for directory in dir_list:
                # 确保目录名称格式正确
                if not directory.startswith('/'):
                    directory = f'/{directory}'
                
                url = f"{target}{directory}"
                future = executor.submit(self._check_url, url, timeout)
                future_to_dir[future] = directory
            
            for future in as_completed(future_to_dir):
                directory = future_to_dir[future]
                try:
                    result = future.result()
                    if result:
                        directories.append(result)
                        self.log_debug(f"发现目录: {directory} (状态码: {result['status_code']})")
                except Exception as e:
                    self.log_debug(f"检查目录 {directory} 失败: {str(e)}")
        
        # 按状态码排序
        directories.sort(key=lambda x: x['status_code'])
        return directories
    
    def _scan_files(self, target, directories, timeout):
        """
        扫描文件
        
        Args:
            target: 目标URL
            directories: 已发现的目录列表
            timeout: 超时时间
        
        Returns:
            list: 发现的文件列表
        """
        files = []
        
        # 常见文件名
        common_filenames = [
            'index', 'default', 'home', 'main', 'config', 'settings',
            'admin', 'login', 'test', 'debug', 'backup', 'old', 'temp'
        ]
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_file = {}
            
            # 扫描根目录和发现的目录中的文件
            dirs_to_scan = ['/'] + [d['path'] for d in directories if d['status_code'] in [200, 403]]
            
            for directory in dirs_to_scan:
                for filename in common_filenames:
                    for ext in self.extensions:
                        if directory == '/':
                            file_path = f"/{filename}{ext}"
                        else:
                            file_path = f"{directory}/{filename}{ext}"
                        
                        url = f"{target}{file_path}"
                        future = executor.submit(self._check_url, url, timeout)
                        future_to_file[future] = file_path
            
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    if result and result['status_code'] == 200:  # 只记录成功的文件
                        files.append(result)
                        self.log_debug(f"发现文件: {file_path}")
                except Exception as e:
                    self.log_debug(f"检查文件 {file_path} 失败: {str(e)}")
        
        return files
    
    def _check_url(self, url, timeout):
        """
        检查URL是否可访问
        
        Args:
            url: URL
            timeout: 超时时间
        
        Returns:
            dict or None: URL信息或None
        """
        try:
            response = requests.get(url, timeout=timeout, headers=self.headers, 
                                  allow_redirects=False, verify=False)
            
            if response.status_code in self.status_codes:
                # 获取内容类型和长度
                content_type = response.headers.get('Content-Type', '')
                content_length = response.headers.get('Content-Length', len(response.content))
                
                # 检查是否有目录列表
                is_directory_listing = self._is_directory_listing(response.text, content_type)
                
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'path': url.split('/', 3)[-1] if len(url.split('/', 3)) > 3 else '/',
                    'content_type': content_type,
                    'content_length': content_length,
                    'redirect_url': response.headers.get('Location'),
                    'directory_listing': is_directory_listing
                }
            
            return None
            
        except requests.exceptions.Timeout:
            self.log_debug(f"请求超时: {url}")
            return None
        except requests.exceptions.ConnectionError:
            self.log_debug(f"连接错误: {url}")
            return None
        except Exception as e:
            self.log_debug(f"检查URL失败 {url}: {str(e)}")
            return None
    
    def _is_directory_listing(self, content, content_type):
        """
        检查是否为目录列表
        
        Args:
            content: 页面内容
            content_type: 内容类型
        
        Returns:
            bool: 是否为目录列表
        """
        if 'text/html' not in content_type:
            return False
        
        directory_indicators = [
            'directory listing',
            'index of',
            '<title>Index of',
            'directory of',
            'parent directory',
            'last modified'
        ]
        
        content_lower = content.lower()
        for indicator in directory_indicators:
            if indicator in content_lower:
                return True
        
        return False
