#!/usr/bin/env python3
"""
Simple run script for the Insider Threat Detection Flask app
This ensures the app starts reliably for deployment
"""

import os
import sys
import logging
from app import app

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Main entry point for the Flask application"""
    try:
        # Get port from environment variable or use default
        port = int(os.environ.get('PORT', 5000))
        
        # Start background monitoring thread
        from threading import Thread
        
        def start_background_monitor():
            """Start background monitoring in a separate thread"""
            try:
                from app import background_monitor
                monitor_thread = Thread(target=background_monitor)
                monitor_thread.daemon = True
                monitor_thread.start()
                logger.info("Background monitoring thread started")
            except Exception as e:
                logger.warning(f"Could not start background monitor: {str(e)}")
        
        # Start background monitoring
        start_background_monitor()
        
        # Run the Flask app
        logger.info(f"Starting Insider Threat Detection Server on port {port}")
        app.run(
            host='0.0.0.0',
            port=port,
            debug=False,
            threaded=True,
            use_reloader=False
        )
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()