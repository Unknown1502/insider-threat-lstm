# GitHub Repository File Structure

## Core Application Files (Root Directory)

### Python Files
- `app.py` - Main Flask application
- `run.py` - Application entry point
- `alert_manager.py` - Alert management system
- `cert_dataset.py` - CERT dataset downloader and loader
- `cim_transformer.py` - Common Information Model transformer
- `data_processor.py` - Data preprocessing and feature engineering
- `lstm_model.py` - LSTM neural network model
- `models.py` - Database models (SQLAlchemy)
- `splunk_backend.py` - Splunk integration backend

### Configuration Files
- `Procfile` - Process configuration for deployment
- `pyproject.toml` - Python project configuration
- `startup.sh` - Startup script for production
- `requirements.txt` - Python dependencies (use content from dependencies.txt)
- `.gitignore` - Git ignore rules
- `README.md` - Project documentation
- `LICENSE` - License file (add your preferred license)

## Templates Directory (`templates/`)
- `index.html` - Main homepage
- `dashboard.html` - Real-time monitoring dashboard
- `model_training.html` - Model training interface
- `alerts.html` - Security alerts page

## Static Files Directory (`static/`)

### CSS (`static/css/`)
- `style.css` - Main stylesheet

### JavaScript (`static/js/`)
- `dashboard.js` - Dashboard functionality
- `model_training.js` - Model training interface scripts

## Configuration Directory (`default/`)
- `app.conf` - Application configuration
- `inputs.conf` - Input configuration
- `props.conf` - Properties configuration
- `transforms.conf` - Transform configuration

## Scripts Directory (`bin/`)
- `insider_threat_detection.py` - Splunk command script

## Data Directory (`data/`)
- `cert_dataset/` - Directory for CERT dataset (add to .gitignore)
- Sample data files will be generated automatically

## Lookups Directory (`lookups/`)
- `threat_indicators.csv` - Threat indicator lookup table

## Models Directory (`models/`)
- Directory for trained models (add to .gitignore)
- Models will be generated during training

## Additional Files to Create

### Environment Configuration
Create `.env.example`:
```
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost/insider_threat_db

# Splunk Configuration
SPLUNK_ENABLED=false
SPLUNK_HOST=your-splunk-server
SPLUNK_PORT=8089
SPLUNK_USERNAME=your-username
SPLUNK_PASSWORD=your-password
SPLUNK_VERIFY_SSL=true

# Application Configuration
FLASK_ENV=production
PORT=5000
```

### Docker Support (Optional)
Create `Dockerfile`:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "run.py"]
```

Create `docker-compose.yml`:
```yaml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/insider_threat_db
    depends_on:
      - db
  
  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=insider_threat_db
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

## Important Notes

1. **Don't include these files in GitHub:**
   - `.replit` (Replit-specific)
   - `__pycache__/` (Python cache)
   - `.pythonlibs/` (Replit libraries)
   - `uv.lock` (Replit lock file)
   - `.config/` (Replit config)
   - `.cache/` (Cache files)
   - `data/alerts.db` (Database file)
   - `models/*.h5` (Trained models)

2. **Security:**
   - Never commit actual API keys or passwords
   - Use environment variables for sensitive data
   - Include `.env.example` but not `.env`

3. **Data Files:**
   - The CERT dataset will be downloaded automatically
   - Sample data is generated for testing
   - Don't commit large data files

4. **Models:**
   - Trained models are generated during runtime
   - Don't commit model files (they're large)
   - Include training scripts instead

## Quick Setup Commands

After cloning your repository:

```bash
# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your actual values

# Run the application
python run.py
```

## File Priorities

**Essential files to include:**
1. All Python files (app.py, run.py, etc.)
2. All template files (templates/*.html)
3. All static files (static/css/*.css, static/js/*.js)
4. Configuration files (Procfile, pyproject.toml, etc.)
5. README.md and documentation

**Optional but recommended:**
1. Docker files for containerization
2. Environment configuration examples
3. Additional documentation
4. Tests (if you add them later)

This structure provides a complete, production-ready insider threat detection system that others can clone and run immediately.