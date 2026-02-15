# Logstash pfSense Parser Visualizer

A web-based tool for visualizing how Logstash configurations parse pfSense syslog entries step by step.

## Features

- 📤 **Upload or paste** Logstash configuration files
- 📝 **Test log entries** with real-time parsing visualization
- 🔍 **Step-by-step breakdown** of the parsing pipeline
- 🎨 **Visual field tracking** showing added, modified, and removed fields
- 📊 **Summary statistics** for parsing results
- 🔧 **Support for common Logstash filters**:
  - Grok pattern matching
  - Mutate operations
  - Date parsing
  - CSV parsing
  - Dissect
  - GeoIP
  - And more!

## Usage

1. **Open the tool**: Simply open `index.html` in your web browser

2. **Load your configuration**:
   - Upload a `.conf` file using the file input, OR
   - Paste your Logstash configuration directly into the text area

3. **Enter a log entry**:
   - Type or paste a pfSense syslog entry, OR
   - Use one of the sample log buttons (Firewall, DHCP, OpenVPN)

4. **Click "Parse Log Entry"** to see the magic happen!

5. **Explore the results**:
   - View the parsing summary statistics
   - Click on each pipeline step to expand/collapse details
   - See which fields were added, modified, or removed at each stage
   - Review the filter configurations and extracted values

## Sample Logs Included

The tool comes with sample pfSense log entries for:
- **Firewall Filter Logs** - Network traffic filtering events
- **DHCP Logs** - DHCP lease assignments
- **OpenVPN Logs** - VPN connection events

## Supported Logstash Filters

- **grok** - Pattern matching and field extraction
- **mutate** - Field transformations (add, remove, rename, convert, etc.)
- **date** - Timestamp parsing
- **csv** - Comma-separated value parsing
- **dissect** - Delimiter-based parsing
- **geoip** - Geographic IP information
- **kv** - Key-value pair parsing
- **json** - JSON data parsing

## How It Works

1. The tool parses your Logstash configuration to identify filter plugins
2. For each filter, it extracts the configuration parameters
3. It then simulates Logstash processing by applying each filter sequentially
4. At each step, it tracks which fields are added, modified, or removed
5. Finally, it presents a visual representation of the entire pipeline

## Grok Pattern Support

The tool includes support for common Grok patterns:
- Network patterns (IP, PORT, MAC, etc.)
- Syslog patterns
- Timestamp patterns
- pfSense-specific patterns

## Files

- `index.html` - Main HTML structure
- `styles.css` - Styling and layout
- `logstash-parser.js` - Core parsing engine
- `app.js` - Application logic and UI handling
- `README.md` - This file

## Browser Compatibility

Works in all modern browsers:
- Chrome/Edge (recommended)
- Firefox
- Safari

No server or installation required - runs entirely in the browser!

## Tips

- Start with the sample configuration to understand the format
- Use the sample logs to test different parsing scenarios
- Click on pipeline steps to collapse/expand them for easier navigation
- Green-highlighted fields are newly added
- Orange-highlighted fields were modified
- Struck-through fields were removed

## Limitations

This is a simulation tool and may not perfectly replicate all Logstash behaviors:
- Some advanced Grok patterns may not be fully supported
- Conditional logic is simplified
- Plugin-specific features may vary from actual Logstash
- Custom patterns need to be defined in the configuration

## Future Enhancements

Potential improvements:
- Export parsed results as JSON
- Save/load configurations from browser storage
- Support for more complex conditional logic
- Custom Grok pattern definitions
- Batch log processing
- Performance metrics

## License

Free to use and modify for your needs!

## Support

For issues or questions, please check your Logstash configuration syntax and ensure it matches the expected format.

Happy parsing! 🚀
