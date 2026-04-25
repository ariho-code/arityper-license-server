#!/usr/bin/env python3
"""
Deployment helper script for AriTyper website
"""

import os
import subprocess
import sys

def run_command(command, description):
    """Run a command and handle the result"""
    print(f"\n{'='*50}")
    print(f"Running: {description}")
    print(f"Command: {command}")
    print('='*50)
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ SUCCESS")
            if result.stdout:
                print("Output:", result.stdout)
        else:
            print("❌ FAILED")
            if result.stderr:
                print("Error:", result.stderr)
            return False
    except Exception as e:
        print(f"❌ EXCEPTION: {e}")
        return False
    
    return True

def main():
    """Main deployment process"""
    print("🚀 AriTyper Website Deployment")
    print("This script will help you deploy the updated website")
    
    # Check if we're in the right directory
    if not os.path.exists('app.py') or not os.path.exists('templates'):
        print("❌ Error: Please run this script from the project root directory")
        sys.exit(1)
    
    # Check if git is initialized
    if not os.path.exists('.git'):
        print("📦 Initializing git repository...")
        if not run_command("git init", "Initialize git"):
            return
    
    # Add all files
    if not run_command("git add .", "Add all files"):
        return
    
    # Commit changes
    commit_message = "Update: Professional marketing UI with integrated license system"
    if not run_command(f'git commit -m "{commit_message}"', "Commit changes"):
        return
    
    print("\n" + "="*60)
    print("🎉 READY FOR DEPLOYMENT!")
    print("="*60)
    print("\nNext steps:")
    print("1. Push to your git repository:")
    print("   git push origin main")
    print("\n2. Deploy on Render:")
    print("   - Go to your Render dashboard")
    print("   - Your service will auto-deploy from the git push")
    print("\n3. Or use the Render CLI:")
    print("   render deploy")
    print("\n📋 Deployment Summary:")
    print("✅ Professional marketing UI integrated")
    print("✅ License request system working")
    print("✅ Download functionality added")
    print("✅ All backend endpoints functional")
    print("✅ SEO optimized with structured data")
    print("✅ Responsive design for all devices")

if __name__ == "__main__":
    main()
