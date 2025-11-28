#!/usr/bin/env python3

import os
import re
import sys
import shutil
import subprocess
from pathlib import Path


def clean_build_directories():
    """Clean up build directories before packaging."""
    print("Cleaning build directories...")
    
    # Directories to clean
    build_dirs = ['build', 'dist', '__pycache__']
    
    for dir_name in build_dirs:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"Removed {dir_name}/")
    
    # Remove .spec files
    for spec_file in Path('.').glob('*.spec'):
        os.remove(spec_file)
        print(f"Removed {spec_file}")


def check_pyinstaller():
    """Check if PyInstaller is installed and install it if necessary."""
    try:
        # Try to import PyInstaller to check if it's installed
        import PyInstaller
        return True
    except ImportError:
        print("PyInstaller not found. Installing PyInstaller...")
        try:
            # Install PyInstaller using pip
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller==6.0.0"])
            print("PyInstaller installed successfully.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error installing PyInstaller: {e}")
            return False

def build_executable():
    """Build the executable using PyInstaller."""
    print("Building executable with PyInstaller...")
    
    # Check if PyInstaller is installed
    if not check_pyinstaller():
        print("Failed to build executable: PyInstaller is not installed.")
        return False
    
    # Determine platform-specific separator for --add-data
    data_separator = ';' if os.name == 'nt' else ':'
    
    # Check if optional files exist
    icon_path = 'resources/BAR_logo.ico'
    has_icon = os.path.exists(icon_path)
    has_license = os.path.exists('LICENSE')
    
    # Build PyInstaller command with conditional options
    cmd = [
        sys.executable, "-m", "PyInstaller",
        '--name=BAR',
        '--windowed',
        '--onefile',
        '--exclude-module=PyQt5',
        '--exclude-module=PyQt6',
        '--clean',
        'main.py'
    ]
    
    if has_icon:
        cmd.insert(-1, f'--icon={os.path.abspath(icon_path)}')
    
    if has_license:
        cmd.insert(-1, f'--add-data=LICENSE{data_separator}.')
    
    # Run PyInstaller using subprocess instead of os.system
    try:
        subprocess.check_call(cmd)
        
        # Fix the spec file if it was created and icon exists
        spec_file = 'BAR.spec'
        if has_icon and os.path.exists(spec_file):
            print("Fixing icon in spec file...")
            with open(spec_file, 'r') as f:
                spec_content = f.read()
            
            # Check if icon is in list format (any path variation)
            if re.search(r"icon=\[.*?\]", spec_content):
                # Extract the path from the list format
                icon_match = re.search(r"icon=\[['\"](.*?)['\"]\]", spec_content)
                if icon_match:
                    # Replace with proper string format using double backslashes for Windows paths
                    spec_content = spec_content.replace(
                        f"icon=['{icon_match.group(1)}']", 
                        f"icon='{icon_path.replace('/', '\\')}'"
                    )
                    with open(spec_file, 'w') as f:
                        f.write(spec_content)
                    
                    # Re-run PyInstaller with the fixed spec file
                    print("Re-running PyInstaller with fixed spec file...")
                    subprocess.check_call([sys.executable, "-m", "PyInstaller", spec_file, "--clean"])
            # If icon is already in string format but might have wrong path
            elif "icon='" in spec_content or 'icon="' in spec_content:
                # Use simple string replacement instead of regex
                # Find the current icon path
                icon_match = re.search(r"icon=['\"](.+?)['\"]", spec_content)
                if icon_match:
                    old_path = icon_match.group(0)  # The entire icon='' part
                    new_path = f"icon='{icon_path.replace('/', '\\')}'"  # New path with proper format
                    
                    # Replace the path
                    spec_content = spec_content.replace(old_path, new_path)
                    with open(spec_file, 'w') as f:
                        f.write(spec_content)
                    
                    # Re-run PyInstaller with the fixed spec file
                    print("Re-running PyInstaller with fixed spec file...")
                    subprocess.check_call([sys.executable, "-m", "PyInstaller", spec_file, "--clean"])
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error building executable: {e}")
        return False


def build_cython_extensions():
    """Build Cython extensions for obfuscation and performance."""
    print("Building Cython extensions...")
    try:
        # Check if Cython is installed
        try:
            import Cython
        except ImportError:
            print("Cython not found. Installing Cython...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "Cython"])
            print("Cython installed successfully.")
        
        # Run the setup.py script to build the extensions
        subprocess.check_call([sys.executable, "setup.py", "build_ext", "--inplace"])
        print("Cython extensions built successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error building Cython extensions: {e}")
        print("Continuing with pure Python implementation...")
        return False

def main():
    """Main entry point for the build script."""
    # Clean build directories
    clean_build_directories()
    
    # Build Cython extensions for obfuscation
    build_cython_extensions()
    
    # Build executable
    build_success = build_executable()
    
    if build_success:
        print("\nBuild completed!")
        print("Executable can be found in the 'dist' directory.")
    else:
        print("\nBuild failed!")
        print("Please check the error messages above and ensure all dependencies are installed.")
        print("You can try running: pip install -r requirements.txt")
        sys.exit(1)


if __name__ == "__main__":
    main()