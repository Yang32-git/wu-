"""
API服务器模块
提供RESTful API接口
"""

from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_cors import CORS
from modules.core.recon_engine import ReconEngine
from modules.utils.logger import setup_logger
from modules.utils.config import load_config
import json
import uuid
from datetime import datetime


class APIServer:
    """API服务器类"""
    
    def __init__(self, config, port=8000):
        """
        初始化API服务器
        
        Args:
            config: 配置字典
            port: 服务器端口
        """
        self.config = config
        self.port = port
        self.app = Flask(__name__)
        self.api = Api(self.app)
        
        # 设置日志
        self.logger = setup_logger('api-server', verbose=True)
        
        # 初始化扫描引擎
        self.engine = ReconEngine(config, self.logger)
        
        # 存储扫描任务
        self.tasks = {}
        
        # 配置CORS
        if config.get('api', {}).get('cors_enabled', True):
            CORS(self.app)
        
        # 注册路由
        self._register_routes()
    
    def _register_routes(self):
        """注册API路由"""
        
        class ScanTask(Resource):
            def __init__(self, api_server):
                self.api_server = api_server
            
            def post(self):
                """创建扫描任务"""
                try:
                    data = request.get_json()
                    if not data:
                        return jsonify({'error': 'No data provided'}), 400
                    
                    target = data.get('target')
                    modules = data.get('modules', ['all'])
                    threads = data.get('threads', 30)
                    timeout = data.get('timeout', 5)
                    
                    if not target:
                        return jsonify({'error': 'Target is required'}), 400
                    
                    # 创建任务ID
                    task_id = str(uuid.uuid4())
                    
                    # 存储任务信息
                    self.api_server.tasks[task_id] = {
                        'id': task_id,
                        'target': target,
                        'modules': modules,
                        'status': 'queued',
                        'created_at': datetime.now().isoformat(),
                        'result': None
                    }
                    
                    # 异步执行扫描
                    import threading
                    scan_thread = threading.Thread(
                        target=self.api_server._run_scan,
                        args=(task_id, target, modules, threads, timeout)
                    )
                    scan_thread.daemon = True
                    scan_thread.start()
                    
                    self.api_server.logger.info(f"创建扫描任务: {task_id} - {target}")
                    
                    return jsonify({
                        'task_id': task_id,
                        'status': 'queued',
                        'message': 'Scan task created successfully'
                    }), 202
                
                except Exception as e:
                    self.api_server.logger.error(f"创建扫描任务失败: {str(e)}")
                    return jsonify({'error': str(e)}), 500
            
            def get(self, task_id=None):
                """获取扫描任务状态或结果"""
                try:
                    if task_id:
                        task = self.api_server.tasks.get(task_id)
                        if not task:
                            return jsonify({'error': 'Task not found'}), 404
                        
                        return jsonify(task), 200
                    
                    # 返回所有任务
                    return jsonify(list(self.api_server.tasks.values())), 200
                
                except Exception as e:
                    self.api_server.logger.error(f"获取扫描任务失败: {str(e)}")
                    return jsonify({'error': str(e)}), 500
        
        class ScannerInfo(Resource):
            def __init__(self, api_server):
                self.api_server = api_server
            
            def get(self):
                """获取扫描器信息"""
                try:
                    info = self.api_server.engine.get_scanner_info()
                    return jsonify({
                        'scanners': info,
                        'version': '1.0.0',
                        'api_version': 'v1'
                    }), 200
                
                except Exception as e:
                    self.api_server.logger.error(f"获取扫描器信息失败: {str(e)}")
                    return jsonify({'error': str(e)}), 500
        
        class HealthCheck(Resource):
            def get(self):
                """健康检查"""
                return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()}), 200
        
        # 注册资源
        self.api.add_resource(ScanTask, '/api/v1/scan', '/api/v1/scan/<string:task_id>', 
                             resource_class_args=[self])
        self.api.add_resource(ScannerInfo, '/api/v1/info', resource_class_args=[self])
        self.api.add_resource(HealthCheck, '/api/v1/health')
        
        # 错误处理
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify({'error': 'Endpoint not found'}), 404
        
        @self.app.errorhandler(500)
        def internal_error(error):
            self.logger.error(f"Internal server error: {str(error)}")
            return jsonify({'error': 'Internal server error'}), 500
    
    def _run_scan(self, task_id, target, modules, threads, timeout):
        """
        运行扫描任务
        
        Args:
            task_id: 任务ID
            target: 目标
            modules: 模块列表
            threads: 线程数
            timeout: 超时时间
        """
        try:
            # 更新任务状态
            self.tasks[task_id]['status'] = 'running'
            self.tasks[task_id]['started_at'] = datetime.now().isoformat()
            
            # 执行扫描
            result = self.engine.scan_target(target, modules, threads, timeout)
            
            # 更新任务结果
            self.tasks[task_id]['status'] = 'completed'
            self.tasks[task_id]['completed_at'] = datetime.now().isoformat()
            self.tasks[task_id]['result'] = result
            
            self.logger.info(f"扫描任务完成: {task_id}")
        
        except Exception as e:
            self.logger.error(f"扫描任务失败 {task_id}: {str(e)}")
            self.tasks[task_id]['status'] = 'failed'
            self.tasks[task_id]['error'] = str(e)
            self.tasks[task_id]['completed_at'] = datetime.now().isoformat()
    
    def start(self):
        """启动API服务器"""
        try:
            host = self.config.get('api', {}).get('host', '0.0.0.0')
            port = self.port or self.config.get('api', {}).get('port', 8000)
            debug = self.config.get('api', {}).get('debug', False)
            
            self.logger.info(f"启动API服务器: http://{host}:{port}")
            self.logger.info(f"API文档: http://{host}:{port}/")
            
            self.app.run(host=host, port=port, debug=debug, threaded=True)
        
        except Exception as e:
            self.logger.error(f"启动API服务器失败: {str(e)}")
            raise


# 简单的API客户端示例
class APIClient:
    """API客户端"""
    
    def __init__(self, base_url='http://localhost:8000/api/v1'):
        self.base_url = base_url
        self.session = requests.Session()
    
    def create_scan_task(self, target, modules=['all'], threads=30, timeout=5):
        """创建扫描任务"""
        data = {
            'target': target,
            'modules': modules,
            'threads': threads,
            'timeout': timeout
        }
        
        response = self.session.post(f"{self.base_url}/scan", json=data)
        return response.json()
    
    def get_task_status(self, task_id):
        """获取任务状态"""
        response = self.session.get(f"{self.base_url}/scan/{task_id}")
        return response.json()
    
    def get_all_tasks(self):
        """获取所有任务"""
        response = self.session.get(f"{self.base_url}/scan")
        return response.json()
    
    def get_scanner_info(self):
        """获取扫描器信息"""
        response = self.session.get(f"{self.base_url}/info")
        return response.json()
    
    def health_check(self):
        """健康检查"""
        response = self.session.get(f"{self.base_url}/health")
        return response.json()
