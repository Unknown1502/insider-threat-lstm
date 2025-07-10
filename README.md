# Insider Threat Detection System

A comprehensive insider threat detection application that uses LSTM deep learning models to identify potential security threats from user behavior patterns. Built with Flask and integrated with Splunk for enterprise security monitoring.

## Features

- **LSTM-CNN Hybrid Model**: Advanced deep learning architecture for behavioral analysis
- **Real-time Monitoring**: Live threat detection and alerting system
- **Splunk Integration**: Compatible with Splunk's Common Information Model (CIM)
- **Web Dashboard**: Interactive interface for monitoring and model management
- **PostgreSQL Database**: Scalable storage for threat events and user profiles
- **Research-based**: Implements findings from academic insider threat detection research

## Performance Metrics

- **Accuracy**: 81.48%
- **Precision**: 82.54%
- **Recall**: 98.47%
- **Model Type**: LSTM-CNN hybrid with 3 LSTM layers + 2 Dense layers

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL database
- Node.js (for frontend dependencies)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/insider-threat-detection.git
cd insider-threat-detection
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
export DATABASE_URL="postgresql://user:password@localhost/insider_threat_db"
export SPLUNK_ENABLED=false  # Set to true for Splunk integration
```

4. Run the application:
```bash
python run.py
```

5. Access the web interface at `http://localhost:5000`

## Usage

### Training the Model

1. Navigate to the **Model Training** page
2. Configure training parameters (epochs, batch size, learning rate)
3. Click **Start Training** to begin model training
4. Monitor progress in real-time through the training logs

### Monitoring Threats

1. Visit the **Dashboard** for real-time threat monitoring
2. View recent threat events and statistics
3. Check the **Alerts** page for security notifications
4. Review user behavioral profiles and risk scores

### Splunk Integration

To enable Splunk integration:

1. Set environment variables:
```bash
export SPLUNK_ENABLED=true
export SPLUNK_HOST=your-splunk-server
export SPLUNK_PORT=8089
export SPLUNK_USERNAME=your-username
export SPLUNK_PASSWORD=your-password
```

2. The system will automatically ingest data from Splunk and provide CIM-compliant output

## Architecture

### Components

- **Flask Web App**: Main application interface
- **LSTM Model**: Deep learning engine for threat detection
- **Data Processor**: Handles preprocessing and feature engineering
- **Alert Manager**: Manages threat notifications
- **Splunk Backend**: Integration with Splunk platform
- **PostgreSQL Database**: Stores threat events, user profiles, and alerts

### Model Architecture

- **Input Layer**: Sequences of user activities (150 time steps)
- **LSTM Layers**: 3 layers with 40 hidden units each
- **Dense Layers**: 2 fully connected layers for classification
- **Output**: Binary classification (normal/threat)

## Database Schema

### Tables

- `threat_events`: Individual threat detection events
- `user_profiles`: Behavioral profiles for each user
- `alerts`: Security alerts and notifications
- `model_metrics`: ML model performance tracking
- `dataset_info`: Training dataset information

## API Endpoints

- `POST /api/train_model`: Start model training
- `GET /api/training_status`: Check training progress
- `GET /api/model_metrics`: Get model performance metrics
- `POST /api/real_time_detection`: Process real-time events
- `GET /api/recent_threats`: Retrieve recent threat events
- `GET /api/alerts`: Get security alerts

## Security Features

- SSL certificate verification for Splunk connections
- Input validation and sanitization
- XSS protection in web interface
- SQL injection prevention
- Secure XML parsing (XXE protection)

## Research Foundation

Based on the research paper "Detection of Insider Threats Based On Deep Learning Using LSTM-CNN Model" with the following specifications:

- **Dataset**: CMU CERT Insider Threat Dataset v4.2
- **Features**: 32 distinct user action types
- **Sequence Length**: 150 activities per day
- **Architecture**: LSTM-CNN hybrid model
- **Performance**: 94-95% accuracy target

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Open an issue on GitHub
- Check the documentation
- Review the research paper implementation details

## Deployment

The application is ready for production deployment on platforms like:
- Heroku
- AWS EC2
- Google Cloud Platform
- Docker containers
- Kubernetes clusters

See the deployment documentation for detailed instructions.