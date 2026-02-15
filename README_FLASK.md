# Logstash pfSense Parser Visualizer - Flask Edition

A Flask-based web application for visualizing and debugging Logstash configurations, specifically designed for pfSense log processing.

## Features

✨ **Python Backend** - Robust server-side parsing with proper conditional logic handling
🔗 **Multiple Config Files** - Chain multiple Logstash configurations
📡 **Input Stream Configuration** - Define different input sources with ports and protocols  
🔍 **Step-by-Step Visualization** - See exactly how each filter transforms your data
⚡ **Conditional Logic Support** - Properly handles if/else/else-if statements with nesting
📥 **JSON Export** - Download complete parsing results
🎨 **Beautiful UI** - Modern gradient design with responsive layout

## Installation

### 1. Create a Virtual Environment

```bash
cd /Users/sorpeter/Documents/psELK/Logstash_tool
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

## Running the Application

```bash
python app.py
```

The application will start on `http://localhost:5000`

Open your browser and navigate to the URL.

## Usage

### 1. Configure Input Streams
- Define input sources with type, port, and protocol
- Pre-loaded with pfSense examples (Firewall, DHCP, etc.)
- Add custom streams as needed

### 2. Add Logstash Configurations
- Upload multiple `.conf` files or paste configurations
- Files are processed in order (reorderable)
- Each config shows filter count and preview

### 3. Test Log Entries
- Enter a raw log entry
- Select the input stream it came from
- Click "Parse Log Entry"

### 4. View Results
- See step-by-step processing pipeline
- Green highlights show added fields
- Orange highlights show modified fields
- Red boxes indicate skipped filters (conditions not met)
- Export results as JSON for documentation

## Architecture

### Backend (Python/Flask)
- `app.py` - Flask application and API endpoints
- `logstash_parser.py` - Core parsing engine with conditional logic
- Proper Python regex for Grok patterns
- Robust if/else chain handling

### Frontend (JavaScript)
- `templates/index.html` - Main UI template
- `static/app.js` - Client-side logic and API calls
- `static/styles.css` - Styling

### API Endpoints

- `POST /api/parse` - Parse a log entry through config chain
- `POST /api/validate-config` - Validate a Logstash configuration

## Supported Filters

- ✅ **grok** - Pattern matching with comprehensive Grok patterns
- ✅ **mutate** - Field transformations (add_field, rename, replace, add_tag, remove_tag, etc.)
- ✅ **csv** - Parse CSV data
- ✅ **date** - Date parsing
- ✅ **json** - JSON parsing
- ✅ **Conditionals** - if/else/else-if with proper nesting

## Example Configuration

```ruby
filter {
  if [type] == "suricata" {
    grok { match => { "message" => "..." } }
    mutate { add_field => { "[@metadata][namespace]" => "suricata" } }
  } 
  else {
    grok { match => { "message" => "..." } }
    mutate { add_field => { "[@metadata][namespace]" => "firewall" } }
  }
}
```

## Development

To run in development mode with auto-reload:

```bash
export FLASK_ENV=development
python app.py
```

## License

MIT License

## Author

Created for pfSense/Logstash configuration debugging and visualization.

## Custom Grok Patterns

The tool includes a `patterns/` directory that provides custom grok patterns:

```
patterns/
├── pfelk       # pfSense/OPNsense firewall patterns
├── suricata    # Suricata IDS/IPS patterns
├── haproxy     # HAProxy load balancer patterns
└── README.md   # Pattern documentation
```

**Usage in Logstash configs:**
```ruby
grok {
  patterns_dir => ["/etc/pfelk/patterns"]  # Automatically mapped to ./patterns
  match => { "message" => "%{PFELK_FILTERLOG_DATA}" }
}
```

The patterns are automatically loaded by the parser - no additional configuration needed!

See `patterns/README.md` for details on pattern syntax and adding custom patterns.
