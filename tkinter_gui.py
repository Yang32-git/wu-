#!/usr/bin/env python3
"""
Tkinter GUI启动脚本 - 完全不依赖Flask的桌面界面
"""

import sys
import os
import warnings

# 忽略tkinter的警告
warnings.filterwarnings('ignore')

# 添加模块路径
sys.path.insert(0, os.path.dirname(__file__))

print("=" * 70)
print("网络安全信息收集工具 - Tkinter桌面GUI")
print("=" * 70)
print()

print("正在启动GUI...")
print("这是一个完全不依赖Flask的桌面应用程序")
print("使用Python内置的tkinter库")
print()

try:
    # 检查Python版本
    if sys.version_info < (3, 6):
        print(f"错误: Python版本过低 ({sys.version})")
        print("需要 Python 3.6 或更高版本")
        sys.exit(1)
    
    print(f"✓ Python版本: {sys.version.split()[0]}")
    
    # 检查tkinter
    try:
        import tkinter
        print("✓ tkinter模块可用")
    except ImportError:
        print("✗ tkinter模块不可用")
        print()
        print("解决方案:")
        print("1. Windows: 重新安装Python，勾选'tcl/tk'选项")
        print("2. Linux: sudo apt-get install python3-tk")
        print("3. Mac: 通常预装，如果缺失请重新安装Python")
        sys.exit(1)
    
    # 检查其他依赖
    required_modules = [
        ('modules.core.recon_engine', '核心引擎'),
        ('modules.utils.config', '配置模块'),
        ('modules.utils.logger', '日志模块')
    ]
    
    all_ok = True
    for module_path, module_name in required_modules:
        try:
            __import__(module_path, fromlist=['*'])
            print(f"✓ {module_name}")
        except ImportError as e:
            print(f"✗ {module_name}: {str(e)}")
            all_ok = False
    
    if not all_ok:
        print()
        print("请先安装必要的依赖:")
        print("  pip install -r requirements.txt")
        sys.exit(1)
    
    print()
    print("所有依赖检查通过！")
    print("正在启动GUI窗口...")
    print()
    
    # 导入并启动GUI
    from modules.gui.tkinter_gui import TkinterGUI
    
    gui = TkinterGUI()
    gui.run()
    
except Exception as e:
    print(f"\n启动失败: {str(e)}")
    print()
    print("详细错误信息:")
    import traceback
    traceback.print_exc()
    print()
    print("如果仍然无法启动，说明系统存在深层问题")
    print("建议使用: Python虚拟环境或重新安装Python")
    sys.exit(1)
