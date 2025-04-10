# BAR - Burn After Reading: GitHub Repository Guide

## Files to Include in Your GitHub Repository

When sharing the BAR project on GitHub, include the following files and directories:

### Essential Code and Documentation
- `src/` - All source code files and modules
- `resources/` - Application resources like icons
- `main.py` - Main application entry point
- `build.py` - Build script for creating executables
- `requirements.txt` - Python dependencies
- `README.md` - Project overview and documentation
- `INSTALL.md` - Installation instructions
- `wiki.md` - Detailed project documentation
- `.gitignore` - Specifies which files to exclude
- Any license files (if applicable)

### Configuration Templates
- Include template configuration files (if any)
- Make sure to remove any sensitive information

## Files to Exclude from Your GitHub Repository

The following files and directories should NOT be included in your GitHub repository:

### Build Artifacts
- `build/` - Build directory containing temporary files
- `dist/` - Distribution directory containing compiled executables
- `*.spec` - PyInstaller specification files
- `__pycache__/` - Python cache directories
- `*.py[cod]` - Compiled Python files

### User Data and Sensitive Information
- Any directories containing user data (typically in `~/.bar/`)
- Log files
- Configuration files with sensitive information
- API keys, passwords, or other credentials

### Environment and IDE Files
- Virtual environment directories (venv, env)
- IDE configuration files (.idea/, .vscode/)
- OS-specific files (.DS_Store, Thumbs.db)

## Using the .gitignore File

A `.gitignore` file has been created in your project directory that automatically excludes the files and directories mentioned above. This ensures that only the necessary files are included when you push your code to GitHub.

## Before Pushing to GitHub

1. Review the files in your repository to ensure no sensitive information is included
2. Make sure all necessary documentation is complete and up-to-date
3. Verify that the `.gitignore` file is properly configured
4. Consider adding a license file if you want to specify how others can use your code

## Setting Up Your GitHub Repository

1. Create a new repository on GitHub
2. Initialize Git in your local project directory (if not already done):
   ```
   git init
   ```
3. Add your files:
   ```
   git add .
   ```
4. Commit your changes:
   ```
   git commit -m "Initial commit"
   ```
5. Add your GitHub repository as a remote:
   ```
   git remote add origin https://github.com/yourusername/your-repo-name.git
   ```
6. Push your code to GitHub:
   ```
   git push -u origin main
   ```

By following these guidelines, you'll ensure that your GitHub repository contains all the necessary files for others to use and contribute to your project, while excluding sensitive information and unnecessary build artifacts.