#!/bin/bash
# Startup script for Logstash pfSense Parser Visualizer

echo "🚀 Starting Logstash pfSense Parser Visualizer (Flask Edition)"
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "✅ Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install -q -r requirements.txt

# Start Flask application
echo ""
echo "🌐 Starting Flask server..."
echo "📍 Application will be available at: http://localhost:5000"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python app.py
