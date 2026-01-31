#!/usr/bin/env python3
"""
安装脚本 - 安装依赖和配置环境
"""

import subprocess
import sys
import os
import platform


def install_package(package):
    """安装单个包"""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"✅ 安装成功: {package}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ 安装失败: {package} - {str(e)}")
        return False


def install_requirements():
    """安装requirements.txt中的所有包"""
    print("安装基础依赖包...")
    
    # 基础依赖（必须）
    base_packages = [
        "requests>=2.31.0",
        "dnspython>=2.4.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "PyYAML>=6.0",
        "urllib3>=2.0.0",
        "certifi>=2023.7.22",
        "jinja2>=3.1.0",
    ]
    
    # 可选依赖
    optional_packages = [
        "flask>=2.3.0",
        "flask-restful>=0.3.10",
        "flask-cors>=4.0.0",
        "weasyprint>=60.0",
        "python-whois>=0.8.0",
        "psutil>=5.9.0",
    ]
    
    installed = 0
    total = len(base_packages) + len(optional_packages)
    
    # 安装基础包
    print("\n安装基础依赖...")
    for package in base_packages:
        if install_package(package):
            installed += 1
    
    # 安装可选包
    print("\n安装可选依赖...")
    print("注意: 某些包可能需要系统依赖或编译工具")
    
    for package in optional_packages:
        try:
            if install_package(package):
                installed += 1
        except Exception as e:
            print(f"⚠️  可选包安装失败（可忽略）: {package}")
            print(f"   错误: {str(e)}")
    
    print(f"\n安装完成: {installed}/{total} 个包成功安装")
    return installed >= len(base_packages)


def check_python_version():
    """检查Python版本"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 6):
        print(f"❌ Python版本过低: {sys.version}")
        print("需要 Python 3.6 或更高版本")
        return False
    print(f"✅ Python版本检查通过: {sys.version}")
    return True


def check_system_dependencies():
    """检查系统依赖"""
    print("\n检查系统依赖...")
    
    system = platform.system()
    print(f"操作系统: {system}")
    
    if system == "Windows":
        print("Windows系统 - 确保已安装Visual C++ Redistributable")
    elif system == "Linux":
        print("Linux系统 - 建议安装: build-essential python3-dev")
    elif system == "Darwin":
        print("macOS系统 - 确保已安装Xcode命令行工具")
    
    return True


def setup_directories():
    """创建必要的目录"""
    print("\n创建目录结构...")
    
    directories = [
        "logs",
        "reports",
        "data",
        "templates"
    ]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"[成功] 创建目录: {directory}")
        else:
            print(f"[成功] 目录已存在: {directory}")
    
    return True


def test_imports():
    """测试关键模块导入"""
    print("\n测试模块导入...")
    
    modules = [
        ("requests", "requests"),
        ("dns", "dnspython"),
        ("bs4", "beautifulsoup4"),
        ("yaml", "PyYAML"),
        ("jinja2", "jinja2"),
    ]
    
    all_ok = True
    
    for module_name, package_name in modules:
        try:
            __import__(module_name)
            print(f"✅ {package_name} 导入成功")
        except ImportError as e:
            print(f"❌ {package_name} 导入失败: {str(e)}")
            all_ok = False
    
    # 测试项目模块
    project_modules = [
        "modules.core.recon_engine",
        "modules.utils.logger",
        "modules.utils.config",
    ]
    
    print("\n测试项目模块...")
    for module_name in project_modules:
        try:
            __import__(module_name)
            print(f"✅ {module_name} 导入成功")
        except ImportError as e:
            print(f"❌ {module_name} 导入失败: {str(e)}")
            all_ok = False
    
    return all_ok


def generate_run_scripts():
    """生成运行脚本"""
    print("\n生成运行脚本...")
    
    # Windows批处理脚本
    if platform.system() == "Windows":
        with open("快速启动.bat", "w") as f:
            f.write("@echo off\n")
            f.write("chcp 65001 >nul\n")
            f.write("echo 启动网络安全信息收集工具...\n")
            f.write("python main.py %*\n")
            f.write("pause\n")
        print("✅ 生成 快速启动.bat")
    
    # Unix Shell脚本
    else:
        with open("run.sh", "w") as f:
            f.write("#!/bin/bash\n")
            f.write("echo \"启动网络安全信息收集工具...\"\n")
            f.write("python3 main.py \"$@\"\n")
        os.chmod("run.sh", 0o755)
        print("✅ 生成 run.sh")
    
    return True


def main():
    """主安装函数"""
    print("=" * 60)
    print("网络安全信息收集工具 - 安装程序")
    print("=" * 60)
    print()
    
    steps = [
        ("Python版本检查", check_python_version),
        ("系统依赖检查", check_system_dependencies),
        ("安装依赖包", install_requirements),
        ("创建目录结构", setup_directories),
        ("测试模块导入", test_imports),
        ("生成运行脚本", generate_run_scripts),
    ]
    
    passed = 0
    total = len(steps)
    
    for step_name, step_func in steps:
        print(f"\n{'='*60}")
        print(f"执行: {step_name}")
        print('='*60)
        
        try:
            if step_func():
                passed += 1
                print(f"✅ {step_name} 成功")
            else:
                print(f"❌ {step_name} 失败")
        except Exception as e:
            print(f"❌ {step_name} 异常: {str(e)}")
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*60}")
    print(f"安装完成: {passed}/{total} 步骤成功")
    print('='*60)
    
    if passed == total:
        print("🎉 安装成功！工具已准备就绪。")
        print()
        print("使用方法:")
        print("  快速启动: python main.py -t example.com")
        print("  查看帮助: python main.py --help")
        print("  API模式:  python main.py --api --port 8000")
        print()
        print("详细使用说明请查看: README.md")
        print("使用示例请查看: examples.txt")
        return 0
    elif passed >= total * 0.8:
        print("⚠️  安装基本完成，部分可选功能可能受限")
        print("   工具应该可以正常运行")
        return 0
    else:
        print("❌ 安装失败，请检查错误信息并手动修复")
        print("   常见问题:")
        print("   - 确保网络连接正常")
        print("   - 确保有管理员/root权限")
        print("   - 安装系统编译工具（如build-essential）")
        return 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n安装被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n安装程序错误: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
