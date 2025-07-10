#!/bin/bash

# Instructions for uploading to GitHub
# Replace YOUR_USERNAME with your actual GitHub username
# Replace YOUR_REPOSITORY_NAME with your repository name

echo "=== GitHub Upload Instructions ==="
echo "1. Create a new repository on GitHub first"
echo "2. Copy your repository URL"
echo "3. Replace the URL in the commands below"
echo "4. Run these commands in your terminal:"
echo ""

echo "# Initialize git repository"
echo "git init"
echo ""

echo "# Add all files"
echo "git add ."
echo ""

echo "# Create first commit"
echo "git commit -m 'Initial commit: Insider Threat Detection System'"
echo ""

echo "# Add your GitHub repository as remote"
echo "git remote add origin https://github.com/YOUR_USERNAME/insider-threat-detection.git"
echo ""

echo "# Push to GitHub"
echo "git push -u origin main"
echo ""

echo "=== Files to include in your repository ==="
echo "Essential Python files:"
echo "- app.py"
echo "- run.py"
echo "- alert_manager.py"
echo "- cert_dataset.py"
echo "- cim_transformer.py"
echo "- data_processor.py"
echo "- lstm_model.py"
echo "- models.py"
echo "- splunk_backend.py"
echo ""

echo "Configuration files:"
echo "- Procfile"
echo "- pyproject.toml"
echo "- startup.sh"
echo "- requirements.txt (copy from dependencies.txt)"
echo ""

echo "Web interface files:"
echo "- templates/ (all HTML files)"
echo "- static/ (CSS and JS files)"
echo ""

echo "Documentation:"
echo "- README.md"
echo "- .gitignore"
echo "- GITHUB_FILES_STRUCTURE.md"
echo ""

echo "Configuration directories:"
echo "- default/ (configuration files)"
echo "- bin/ (scripts)"
echo "- lookups/ (CSV files)"
echo ""

echo "=== Don't forget to ==="
echo "1. Copy dependencies.txt content to requirements.txt"
echo "2. Add your license file"
echo "3. Create .env.example from the template"
echo "4. Update README.md with your GitHub username"