#!/usr/bin/env python3
"""
Tkinter桌面GUI - 完全不依赖Flask/SocketIO
使用Python内置的tkinter库，100%兼容
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import json
import time
from datetime import datetime
from pathlib import Path

# 添加模块路径
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from modules.core.recon_engine import ReconEngine
from modules.utils.config import load_config
from modules.utils.logger import setup_logger
from modules.report.report_generator import ReportGenerator


class TkinterGUI:
    """Tkinter桌面GUI类"""
    
    def __init__(self):
        self.config = load_config()
        self.logger = setup_logger('tkinter-gui')
        self.engine = ReconEngine(self.config, self.logger)
        self.scan_thread = None
        self.is_scanning = False
        self.results = {}
        
        # 创建主窗口
        self.root = tk.Tk()
        self.root.title("网络安全信息收集工具")
        self.root.geometry("1200x800")
        
        # 设置样式
        self.setup_styles()
        
        # 创建界面
        self.create_widgets()
        
    def setup_styles(self):
        """设置界面样式"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # 颜色方案
        self.colors = {
            'bg': '#f0f0f0',
            'panel': '#ffffff',
            'primary': '#007bff',
            'success': '#28a745',
            'warning': '#ffc107',
            'danger': '#dc3545',
            'info': '#17a2b8'
        }
    
    def create_widgets(self):
        """创建界面组件"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # 左侧配置面板
        config_frame = self.create_config_panel(main_frame)
        config_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        # 右侧主面板
        right_frame = ttk.Frame(main_frame)
        right_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 进度面板
        progress_frame = self.create_progress_panel(right_frame)
        progress_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # 结果面板
        result_frame = self.create_result_panel(right_frame)
        result_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
    
    def create_config_panel(self, parent):
        """创建配置面板"""
        frame = ttk.LabelFrame(parent, text="扫描配置", padding="10")
        
        # 目标输入
        ttk.Label(frame, text="目标列表（每行一个）:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.targets_text = scrolledtext.ScrolledText(frame, height=6, width=40)
        self.targets_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # 模块选择
        ttk.Label(frame, text="选择扫描模块:").grid(row=2, column=0, sticky=tk.W, pady=(0, 5))
        
        modules_frame = ttk.Frame(frame)
        modules_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.module_vars = {}
        modules = [
            ('subdomain', '子域名扫描'),
            ('port', '端口探测'),
            ('service', '服务识别'),
            ('dns', 'DNS记录'),
            ('whois', 'WHOIS查询'),
            ('dir', '目录扫描'),
            ('vuln', '漏洞检测'),
            ('ssl', 'SSL分析'),
            ('network', '网络拓扑')
        ]
        
        for i, (key, label) in enumerate(modules):
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(modules_frame, text=label, variable=var)
            chk.grid(row=i//2, column=i%2, sticky=tk.W, padx=(0, 20))
            self.module_vars[key] = var
        
        # 参数设置
        params_frame = ttk.Frame(frame)
        params_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(params_frame, text="线程数:").grid(row=0, column=0, sticky=tk.W)
        self.threads_var = tk.StringVar(value="30")
        threads_spin = ttk.Spinbox(params_frame, from_=1, to=200, textvariable=self.threads_var, width=8)
        threads_spin.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        ttk.Label(params_frame, text="超时(秒):").grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        self.timeout_var = tk.StringVar(value="5")
        timeout_spin = ttk.Spinbox(params_frame, from_=1, to=300, textvariable=self.timeout_var, width=8)
        timeout_spin.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=(5, 0))
        
        # 按钮
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=5, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.start_btn = ttk.Button(btn_frame, text="开始扫描", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        
        self.stop_btn = ttk.Button(btn_frame, text="停止扫描", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5, 0))
        
        # 快速预设
        preset_frame = ttk.LabelFrame(frame, text="快速预设", padding="5")
        preset_frame.grid(row=6, column=0, sticky=(tk.W, tk.E))
        
        ttk.Button(preset_frame, text="信息收集", command=lambda: self.apply_preset('recon')).pack(side=tk.LEFT, padx=2)
        ttk.Button(preset_frame, text="安全评估", command=lambda: self.apply_preset('security')).pack(side=tk.LEFT, padx=2)
        ttk.Button(preset_frame, text="网络探测", command=lambda: self.apply_preset('network')).pack(side=tk.LEFT, padx=2)
        
        return frame
    
    def create_progress_panel(self, parent):
        """创建进度面板"""
        frame = ttk.LabelFrame(parent, text="扫描进度", padding="10")
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.current_target_var = tk.StringVar(value="等待开始扫描...")
        ttk.Label(frame, textvariable=self.current_target_var).grid(row=1, column=0, sticky=tk.W)
        
        self.stats_var = tk.StringVar(value="就绪")
        ttk.Label(frame, textvariable=self.stats_var).grid(row=2, column=0, sticky=tk.W, pady=(5, 0))
        
        return frame
    
    def create_result_panel(self, parent):
        """创建结果面板"""
        frame = ttk.LabelFrame(parent, text="扫描结果", padding="10")
        
        # 按钮框架
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Button(btn_frame, text="保存报告", command=self.save_report).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="清空结果", command=self.clear_results).pack(side=tk.LEFT, padx=(10, 0))
        
        # 结果树
        self.result_tree = ttk.Treeview(frame, columns=('value',), height=20)
        self.result_tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.result_tree.column('#0', width=300, anchor=tk.W)
        self.result_tree.column('value', width=600, anchor=tk.W)
        
        self.result_tree.heading('#0', text='项目')
        self.result_tree.heading('value', text='值')
        
        # 滚动条
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.result_tree.yview)
        scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        self.result_tree.configure(yscrollcommand=scrollbar.set)
        
        return frame
    
    def apply_preset(self, preset_type):
        """应用快速预设"""
        # 清除所有选择
        for var in self.module_vars.values():
            var.set(False)
        
        if preset_type == 'recon':
            modules = ['subdomain', 'dns', 'whois']
        elif preset_type == 'security':
            modules = ['port', 'service', 'vuln', 'ssl']
        elif preset_type == 'network':
            modules = ['port', 'service', 'network']
        else:
            return
        
        for module in modules:
            if module in self.module_vars:
                self.module_vars[module].set(True)
        
        self.status_var.set(f"已加载{preset_type}预设")
    
    def start_scan(self):
        """开始扫描"""
        # 获取目标
        targets_text = self.targets_text.get('1.0', tk.END).strip()
        if not targets_text:
            messagebox.showerror("错误", "请输入扫描目标")
            return
        
        targets = [t.strip() for t in targets_text.split('\n') if t.strip()]
        
        # 获取模块
        modules = [key for key, var in self.module_vars.items() if var.get()]
        if not modules:
            messagebox.showerror("错误", "请选择至少一个扫描模块")
            return
        
        # 获取参数
        try:
            threads = int(self.threads_var.get())
            timeout = int(self.timeout_var.get())
        except ValueError:
            messagebox.showerror("错误", "线程数和超时时间必须是数字")
            return
        
        # 确认对话框
        confirm = messagebox.askyesno(
            "确认开始扫描",
            f"扫描目标: {len(targets)}个\n扫描模块: {', '.join(modules)}\n线程数: {threads}\n超时: {timeout}秒\n\n是否开始扫描？"
        )
        
        if not confirm:
            return
        
        # 开始扫描
        self.is_scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.clear_results()
        
        # 创建扫描线程
        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(targets, modules, threads, timeout)
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        self.status_var.set("扫描进行中...")
    
    def stop_scan(self):
        """停止扫描"""
        if self.is_scanning:
            confirm = messagebox.askyesno("确认停止", "是否停止当前扫描？")
            if confirm:
                self.is_scanning = False
                self.status_var.set("扫描已停止")
                self.start_btn.config(state=tk.NORMAL)
                self.stop_btn.config(state=tk.DISABLED)
    
    def run_scan(self, targets, modules, threads, timeout):
        """运行扫描"""
        total_targets = len(targets)
        
        for i, target in enumerate(targets):
            if not self.is_scanning:
                break
            
            # 更新进度
            progress = (i / total_targets) * 100
            self.progress_var.set(progress)
            self.current_target_var.set(f"当前目标: {target}")
            self.stats_var.set(f"进度: {i+1}/{total_targets}")
            
            try:
                # 执行扫描
                result = self.engine.scan_target(target, modules, threads, timeout)
                self.results[target] = result
                
                # 更新UI
                self.root.after(0, self.update_results, target, result)
                
            except Exception as e:
                self.logger.error(f"扫描 {target} 失败: {str(e)}")
                self.results[target] = {'error': str(e)}
        
        # 扫描完成
        self.is_scanning = False
        self.root.after(0, self.scan_complete)
    
    def update_results(self, target, result):
        """更新结果树"""
        # 添加目标节点
        target_node = self.result_tree.insert('', 'end', text=target, open=True)
        
        if result.get('success', False):
            # 添加基本信息
            self.result_tree.insert(target_node, 'end', text='状态', values=('成功',))
            self.result_tree.insert(target_node, 'end', text='耗时', values=(f"{result.get('duration', 0)}秒",))
            
            # 添加模块结果
            results = result.get('results', {})
            for module, module_result in results.items():
                if module_result.get('success', False):
                    module_node = self.result_tree.insert(target_node, 'end', text=f'模块: {module}', open=True)
                    self.update_module_results(module_node, module, module_result.get('data', {}))
        else:
            self.result_tree.insert(target_node, 'end', text='错误', values=(result.get('error', '未知错误'),))
    
    def update_module_results(self, parent_node, module, data):
        """更新模块结果"""
        if module == 'dns' and data.get('records'):
            for record_type, records in data['records'].items():
                record_node = self.result_tree.insert(parent_node, 'end', text=f'{record_type}记录', open=False)
                for record in records[:5]:  # 只显示前5条
                    self.result_tree.insert(record_node, 'end', text='', values=(str(record),))
                if len(records) > 5:
                    self.result_tree.insert(record_node, 'end', text='', values=(f'...还有{len(records)-5}条',))
        
        elif module == 'whois':
            for key, value in data.items():
                if value:
                    self.result_tree.insert(parent_node, 'end', text=key, values=(str(value),))
        
        elif module == 'subdomain' and data.get('subdomains'):
            self.result_tree.insert(parent_node, 'end', text=f"发现 {data.get('total_found', 0)} 个子域名", values=('',))
            for subdomain in data['subdomains'][:10]:
                self.result_tree.insert(parent_node, 'end', text='', values=(subdomain,))
        
        elif module == 'port' and data.get('open_ports'):
            self.result_tree.insert(parent_node, 'end', text=f"开放端口: {data.get('open_count', 0)} 个", values=('',))
            for port_info in data['open_ports']:
                port_str = f"端口 {port_info['port']} ({port_info['service']}) - {port_info['state']}"
                self.result_tree.insert(parent_node, 'end', text='', values=(port_str,))
    
    def scan_complete(self):
        """扫描完成"""
        self.progress_var.set(100)
        self.status_var.set("扫描完成")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        total_targets = len(self.results)
        completed = sum(1 for r in self.results.values() if r.get('status') == 'completed')
        
        messagebox.showinfo("扫描完成", f"扫描完成！\n总目标: {total_targets}\n完成: {completed}")
    
    def save_report(self):
        """保存报告"""
        if not self.results:
            messagebox.showwarning("警告", "没有扫描结果可保存")
            return
        
        # 选择保存路径
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML文件", "*.html"), ("JSON文件", "*.json"), ("所有文件", "*.*")],
            initialfile=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
        
        if not filename:
            return
        
        try:
            report_gen = ReportGenerator(self.config, self.logger)
            
            if filename.endswith('.json'):
                # 保存JSON
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=2, ensure_ascii=False)
            else:
                # 保存HTML
                scan_results = {target: {'results': result} for target, result in self.results.items()}
                report_gen.generate_html_report(scan_results, filename)
            
            messagebox.showinfo("保存成功", f"报告已保存到:\n{filename}")
            
        except Exception as e:
            messagebox.showerror("保存失败", f"保存报告时出错:\n{str(e)}")
    
    def clear_results(self):
        """清空结果"""
        confirm = messagebox.askyesno("确认清空", "确定要清空所有扫描结果吗？")
        if confirm:
            self.result_tree.delete(*self.result_tree.get_children())
            self.results = {}
            self.progress_var.set(0)
            self.current_target_var.set("等待开始扫描...")
            self.stats_var.set("就绪")
            self.status_var.set("就绪")
    
    def run(self):
        """运行GUI"""
        # 窗口居中
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
        print("=" * 70)
        print("网络安全信息收集工具 - Tkinter桌面GUI")
        print("=" * 70)
        print("GUI已启动！")
        print("这是一个完全不依赖Flask的桌面应用程序")
        print("使用Python内置的tkinter库，100%兼容")
        print("=" * 70)
        
        self.root.mainloop()


def main():
    """主函数"""
    print("=" * 70)
    print("启动Tkinter桌面GUI...")
    print("=" * 70)
    
    # 检查tkinter是否可用
    try:
        import tkinter
        print("✓ tkinter模块可用")
    except ImportError:
        print("✗ tkinter模块不可用")
        print("请安装tkinter:")
        print("  Windows: Python安装时勾选'tcl/tk'选项")
        print("  Linux: sudo apt-get install python3-tk")
        print("  Mac: 通常预装，不需要额外安装")
        sys.exit(1)
    
    # 创建并运行GUI
    try:
        gui = TkinterGUI()
        gui.run()
    except Exception as e:
        print(f"启动失败: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n程序已终止")
        sys.exit(0)
