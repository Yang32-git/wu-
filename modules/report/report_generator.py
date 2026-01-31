"""
报告生成器模块
生成HTML和JSON格式的扫描报告
"""

import json
import os
from pathlib import Path
from datetime import datetime
from modules.utils.logger import get_logger


class ReportGenerator:
    """报告生成器类"""
    
    def __init__(self, config, logger=None):
        """
        初始化报告生成器
        
        Args:
            config: 配置字典
            logger: 日志记录器
        """
        self.config = config
        self.logger = logger or get_logger()
        
        # 模板目录
        self.template_dir = Path(__file__).parent.parent.parent / 'templates'
        self.template_dir.mkdir(exist_ok=True)
    
    def generate_report(self, scan_results, output_file):
        """
        生成报告
        
        Args:
            scan_results: 扫描结果字典
            output_file: 输出文件路径
        """
        try:
            # 确定报告格式
            file_ext = Path(output_file).suffix.lower()
            
            if file_ext == '.html':
                self.generate_html_report(scan_results, output_file)
            elif file_ext == '.json':
                self.generate_json_report(scan_results, output_file)
            elif file_ext == '.pdf':
                self.generate_pdf_report(scan_results, output_file)
            else:
                # 默认为HTML
                output_file = str(output_file) + '.html'
                self.generate_html_report(scan_results, output_file)
            
            self.logger.info(f"报告已生成: {output_file}")
            
        except Exception as e:
            self.logger.error(f"生成报告失败: {str(e)}")
            raise
    
    def generate_html_report(self, scan_results, output_file):
        """
        生成HTML报告
        
        Args:
            scan_results: 扫描结果
            output_file: 输出HTML文件路径
        """
        try:
            # 准备报告数据
            report_data = self._prepare_report_data(scan_results)
            
            # 生成HTML内容
            html_content = self._generate_html_content(report_data)
            
            # 写入文件
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
        except Exception as e:
            self.logger.error(f"生成HTML报告失败: {str(e)}")
            raise
    
    def generate_json_report(self, scan_results, output_file):
        """
        生成JSON报告
        
        Args:
            scan_results: 扫描结果
            output_file: 输出JSON文件路径
        """
        try:
            # 准备报告数据
            report_data = self._prepare_report_data(scan_results)
            
            # 写入JSON文件
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
        except Exception as e:
            self.logger.error(f"生成JSON报告失败: {str(e)}")
            raise
    
    def generate_pdf_report(self, scan_results, output_file):
        """
        生成PDF报告
        
        Args:
            scan_results: 扫描结果
            output_file: 输出PDF文件路径
        """
        try:
            # 首先生成HTML，然后转换为PDF
            import tempfile
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as tmp_file:
                # 生成HTML报告
                self.generate_html_report(scan_results, tmp_file.name)
                
                # 转换为PDF
                self._convert_html_to_pdf(tmp_file.name, output_file)
                
                # 清理临时文件
                os.unlink(tmp_file.name)
            
        except Exception as e:
            self.logger.error(f"生成PDF报告失败: {str(e)}")
            raise
    
    def _prepare_report_data(self, scan_results):
        """
        准备报告数据
        
        Args:
            scan_results: 扫描结果
        
        Returns:
            dict: 报告数据
        """
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool_name': '网络安全信息收集工具',
                'version': '1.0.0',
                'author': self.config.get('report', {}).get('author', '网络安全团队'),
                'company': self.config.get('report', {}).get('company', '安全实验室')
            },
            'summary': {
                'total_targets': len(scan_results),
                'total_vulnerabilities': 0,
                'total_warnings': 0,
                'risk_level': 'low'
            },
            'targets': []
        }
        
        # 处理每个目标的结果
        for target, result in scan_results.items():
            if result.get('success', False):
                target_data = self._process_target_result(target, result)
                report_data['targets'].append(target_data)
                
                # 更新统计信息
                report_data['summary']['total_vulnerabilities'] += target_data.get('total_vulnerabilities', 0)
                report_data['summary']['total_warnings'] += target_data.get('total_warnings', 0)
        
        # 计算总体风险等级
        report_data['summary']['risk_level'] = self._calculate_overall_risk(report_data['targets'])
        
        return report_data
    
    def _process_target_result(self, target, result):
        """
        处理单个目标的扫描结果
        
        Args:
            target: 目标
            result: 扫描结果
        
        Returns:
            dict: 处理后的目标数据
        """
        target_data = {
            'target': target,
            'status': result.get('status', 'unknown'),
            'start_time': result.get('start_time'),
            'end_time': result.get('end_time'),
            'duration': result.get('duration'),
            'modules': result.get('modules', []),
            'results': {},
            'total_vulnerabilities': 0,
            'total_warnings': 0,
            'total_info': 0,
            'risk_level': 'low'
        }
        
        # 处理每个模块的结果
        results = result.get('results', {})
        for module, module_result in results.items():
            if module_result.get('success', False):
                processed_result = self._process_module_result(module, module_result.get('data', {}))
                target_data['results'][module] = processed_result
                
                # 统计漏洞、警告和信息
                target_data['total_vulnerabilities'] += processed_result.get('vulnerability_count', 0)
                target_data['total_warnings'] += processed_result.get('warning_count', 0)
                target_data['total_info'] += processed_result.get('info_count', 0)
        
        # 计算风险等级
        target_data['risk_level'] = self._calculate_risk_level(target_data)
        
        return target_data
    
    def _process_module_result(self, module, data):
        """
        处理模块结果
        
        Args:
            module: 模块名称
            data: 模块数据
        
        Returns:
            dict: 处理后的模块数据
        """
        processed = {
            'module': module,
            'vulnerability_count': 0,
            'warning_count': 0,
            'info_count': 0
        }
        
        if module == 'subdomain':
            processed['subdomains'] = data.get('subdomains', [])
            processed['total_found'] = data.get('total_found', 0)
        
        elif module == 'port':
            processed['open_ports'] = data.get('open_ports', [])
            processed['open_count'] = data.get('open_count', 0)
        
        elif module == 'service':
            processed['services'] = data.get('services', [])
            processed['os_guess'] = data.get('os_guess')
        
        elif module == 'dns':
            processed['records'] = data.get('records', {})
            processed['total_records'] = data.get('total_records', 0)
        
        elif module == 'whois':
            processed['domain_name'] = data.get('domain_name')
            processed['registrar'] = data.get('registrar')
            processed['creation_date'] = data.get('creation_date')
            processed['expiration_date'] = data.get('expiration_date')
        
        elif module == 'dir':
            processed['directories'] = data.get('directories', [])
            processed['files'] = data.get('files', [])
            processed['total_found'] = data.get('total_found', 0)
        
        elif module == 'vuln':
            processed['vulnerabilities'] = data.get('vulnerabilities', [])
            processed['warnings'] = data.get('warnings', [])
            processed['info'] = data.get('info', [])
            processed['vulnerability_count'] = data.get('total_vulnerabilities', 0)
            processed['warning_count'] = len(data.get('warnings', []))
            processed['info_count'] = len(data.get('info', []))
            processed['risk_level'] = data.get('risk_level', 'low')
        
        elif module == 'ssl':
            processed['certificates'] = data.get('certificates', [])
            processed['vulnerabilities'] = data.get('vulnerabilities', [])
            processed['warnings'] = data.get('warnings', [])
            processed['vulnerability_count'] = len(data.get('vulnerabilities', []))
            processed['warning_count'] = len(data.get('warnings', []))
        
        elif module == 'network':
            processed['traceroute'] = data.get('traceroute')
            processed['network_info'] = data.get('network_info', {})
            processed['os_guess'] = data.get('os_guess')
        
        return processed
    
    def _calculate_risk_level(self, target_data):
        """
        计算风险等级
        
        Args:
            target_data: 目标数据
        
        Returns:
            str: 风险等级
        """
        vuln_count = target_data.get('total_vulnerabilities', 0)
        warning_count = target_data.get('total_warnings', 0)
        
        if vuln_count > 0:
            return 'critical'
        elif warning_count >= 3:
            return 'high'
        elif warning_count >= 1:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_overall_risk(self, targets):
        """
        计算总体风险等级
        
        Args:
            targets: 目标列表
        
        Returns:
            str: 总体风险等级
        """
        if not targets:
            return 'low'
        
        risk_levels = [target.get('risk_level', 'low') for target in targets]
        
        if 'critical' in risk_levels:
            return 'critical'
        elif risk_levels.count('high') >= 2:
            return 'high'
        elif 'high' in risk_levels:
            return 'medium'
        else:
            return 'low'
    
    def _generate_html_content(self, report_data):
        """
        生成HTML内容
        
        Args:
            report_data: 报告数据
        
        Returns:
            str: HTML内容
        """
        html_template = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>网络安全扫描报告</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            border-left: 4px solid #007bff;
            padding-left: 15px;
            margin-top: 30px;
        }}
        h3 {{
            color: #666;
            margin-top: 20px;
        }}
        .summary {{
            background-color: #e9ecef;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .summary-item {{
            display: inline-block;
            margin: 10px 20px;
            text-align: center;
        }}
        .summary-value {{
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
        }}
        .risk-critical {{
            background-color: #dc3545;
            color: white;
            padding: 5px 15px;
            border-radius: 3px;
            display: inline-block;
        }}
        .risk-high {{
            background-color: #fd7e14;
            color: white;
            padding: 5px 15px;
            border-radius: 3px;
            display: inline-block;
        }}
        .risk-medium {{
            background-color: #ffc107;
            color: black;
            padding: 5px 15px;
            border-radius: 3px;
            display: inline-block;
        }}
        .risk-low {{
            background-color: #28a745;
            color: white;
            padding: 5px 15px;
            border-radius: 3px;
            display: inline-block;
        }}
        .target-section {{
            border: 1px solid #dee2e6;
            margin: 20px 0;
            border-radius: 5px;
            overflow: hidden;
        }}
        .target-header {{
            background-color: #f8f9fa;
            padding: 15px;
            border-bottom: 1px solid #dee2e6;
            font-weight: bold;
        }}
        .target-content {{
            padding: 15px;
        }}
        .module-section {{
            margin: 15px 0;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 5px;
        }}
        .vulnerability {{
            background-color: #f8d7da;
            border-left: 4px solid #dc3545;
            padding: 10px;
            margin: 10px 0;
        }}
        .warning {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 10px;
            margin: 10px 0;
        }}
        .info {{
            background-color: #d1ecf1;
            border-left: 4px solid #17a2b8;
            padding: 10px;
            margin: 10px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            border: 1px solid #dee2e6;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: bold;
        }}
        .metadata {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            font-size: 14px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>网络安全信息收集报告</h1>
        
        <div class="metadata">
            <strong>生成时间:</strong> {generated_at}<br>
            <strong>工具版本:</strong> {version}<br>
            <strong>生成者:</strong> {author}<br>
            <strong>组织:</strong> {company}
        </div>
        
        <div class="summary">
            <h2>执行摘要</h2>
            <div class="summary-item">
                <div class="summary-value">{total_targets}</div>
                <div>扫描目标</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{total_vulnerabilities}</div>
                <div>漏洞总数</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{total_warnings}</div>
                <div>警告总数</div>
            </div>
            <div class="summary-item">
                <div class="summary-value"><span class="risk-{risk_level}">{risk_level.upper()}</span></div>
                <div>总体风险等级</div>
            </div>
        </div>
        
        {targets_content}
        
    </div>
</body>
</html>
        """
        
        # 生成目标内容
        targets_content = ""
        for target in report_data['targets']:
            targets_content += self._generate_target_html(target)
        
        # 格式化HTML
        html_content = html_template.format(
            generated_at=report_data['metadata']['generated_at'],
            version=report_data['metadata']['version'],
            author=report_data['metadata']['author'],
            company=report_data['metadata']['company'],
            total_targets=report_data['summary']['total_targets'],
            total_vulnerabilities=report_data['summary']['total_vulnerabilities'],
            total_warnings=report_data['summary']['total_warnings'],
            risk_level=report_data['summary']['risk_level'],
            targets_content=targets_content
        )
        
        return html_content
    
    def _generate_target_html(self, target_data):
        """
        生成目标的HTML内容
        
        Args:
            target_data: 目标数据
        
        Returns:
            str: HTML内容
        """
        html = f"""
        <div class="target-section">
            <div class="target-header">
                目标: {target_data['target']}
                <span class="risk-{target_data['risk_level']}" style="float: right;">{target_data['risk_level'].upper()}</span>
            </div>
            <div class="target-content">
                <p><strong>扫描时间:</strong> {target_data['start_time']} - {target_data['end_time']}</p>
                <p><strong>耗时:</strong> {target_data['duration']} 秒</p>
                <p><strong>扫描模块:</strong> {', '.join(target_data['modules'])}</p>
                
                <div style="margin: 15px 0;">
                    <strong>统计信息:</strong><br>
                    漏洞: {target_data['total_vulnerabilities']} |
                    警告: {target_data['total_warnings']} |
                    信息: {target_data['total_info']}
                </div>
        """
        
        # 添加模块详情
        for module, module_data in target_data['results'].items():
            html += self._generate_module_html(module, module_data)
        
        html += "</div></div>"
        
        return html
    
    def _generate_module_html(self, module, module_data):
        """
        生成模块的HTML内容
        
        Args:
            module: 模块名称
            module_data: 模块数据
        
        Returns:
            str: HTML内容
        """
        module_names = {
            'subdomain': '子域名扫描',
            'port': '端口扫描',
            'service': '服务识别',
            'dns': 'DNS记录',
            'whois': 'WHOIS信息',
            'dir': '目录扫描',
            'vuln': '漏洞检测',
            'ssl': 'SSL证书分析',
            'network': '网络拓扑'
        }
        
        html = f"""
        <div class="module-section">
            <h3>{module_names.get(module, module.upper())}</h3>
        """
        
        if module == 'subdomain':
            html += f"<p>发现子域名: {module_data.get('total_found', 0)} 个</p>"
            if module_data.get('subdomains'):
                html += "<table><tr><th>子域名</th></tr>"
                for subdomain in module_data['subdomains'][:10]:  # 只显示前10个
                    html += f"<tr><td>{subdomain}</td></tr>"
                if len(module_data['subdomains']) > 10:
                    html += f"<tr><td>... 还有 {len(module_data['subdomains']) - 10} 个</td></tr>"
                html += "</table>"
        
        elif module == 'port':
            html += f"<p>开放端口: {module_data.get('open_count', 0)} 个</p>"
            if module_data.get('open_ports'):
                html += """
                <table>
                    <tr><th>端口</th><th>服务</th><th>状态</th></tr>
                """
                for port in module_data['open_ports']:
                    html += f"<tr><td>{port['port']}</td><td>{port['service']}</td><td>{port['state']}</td></tr>"
                html += "</table>"
        
        elif module == 'vuln' or module == 'ssl':
            # 显示漏洞、警告和信息
            for vuln in module_data.get('vulnerabilities', []):
                html += f"""
                <div class="vulnerability">
                    <strong>[{vuln.get('severity', 'unknown').upper()}] {vuln.get('type', 'Unknown')}</strong><br>
                    {vuln.get('description', '')}<br>
                    <em>建议: {vuln.get('recommendation', '暂无建议')}</em>
                </div>
                """
            
            for warning in module_data.get('warnings', []):
                html += f"""
                <div class="warning">
                    <strong>[{warning.get('severity', 'unknown').upper()}] {warning.get('type', 'Unknown')}</strong><br>
                    {warning.get('description', '')}<br>
                    <em>建议: {warning.get('recommendation', '暂无建议')}</em>
                </div>
                """
            
            for info in module_data.get('info', []):
                html += f"""
                <div class="info">
                    <strong>[{info.get('severity', 'unknown').upper()}] {info.get('type', 'Unknown')}</strong><br>
                    {info.get('description', '')}
                </div>
                """
        
        html += "</div>"
        
        return html
    
    def _convert_html_to_pdf(self, html_file, pdf_file):
        """
        将HTML转换为PDF
        
        Args:
            html_file: HTML文件路径
            pdf_file: PDF输出文件路径
        """
        try:
            from weasyprint import HTML
            
            HTML(filename=html_file).write_pdf(pdf_file)
            
        except ImportError:
            self.logger.error("weasyprint库未安装，无法生成PDF报告")
            raise Exception("PDF生成功能需要安装weasyprint库: pip install weasyprint")
        except Exception as e:
            self.logger.error(f"HTML转PDF失败: {str(e)}")
            raise
