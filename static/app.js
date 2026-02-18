/**
 * Main Application Logic - Flask Edition
 * Uses backend API for parsing
 */

let currentConfig = null;
let configChain = []; // Array to store multiple configs
let inputStreams = []; // Array to store input stream configurations
let selectedPcapContext = null;

// Store last parse result for export
let lastParseResult = null;

// Sample pfSense log entries
const sampleLogs = {
    filterlog: `<134>1 2026-02-12T10:30:45.123456-05:00 pfSense.local filterlog 12345 - - 5,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,192.168.1.100,8.8.8.8,12345,53,0,S,1234567890,,1024,,mss;sackOK;TS`,
    dhcp_discover: `<30>Feb 12 10:45:20 pfSense dhcpd: DHCPDISCOVER from aa:bb:cc:dd:ee:ff via igb1`,
    dhcp_offer: `<30>Feb 12 10:45:20 pfSense dhcpd: DHCPOFFER on 192.168.1.150 to aa:bb:cc:dd:ee:ff via igb1`,
    dhcp_ack: `<30>Feb 12 10:45:23 pfSense dhcpd: DHCPACK on 192.168.1.150 to aa:bb:cc:dd:ee:ff (Johns-iPhone) via igb1`,
    dhcp_nack: `<30>Feb 12 10:46:10 pfSense dhcpd: DHCPNAK on 192.168.1.100 to aa:bb:cc:dd:ee:ff via igb1`,
    dhcp_release: `<30>Feb 12 10:50:45 pfSense dhcpd: DHCPRELEASE of 192.168.1.150 from aa:bb:cc:dd:ee:ff via igb1`,
    openvpn: `<134>Feb 12 11:20:15 pfSense openvpn[54321]: 192.168.10.5:12345 [client1] Peer Connection Initiated with [AF_INET]192.168.10.5:12345`,
    sshguard_attack: `1 2026-02-15T22:27:15.063047+01:00 pfSense.lohdal.com sshguard 6554 - - Attack from "192.168.178.58" on service unknown service with danger 10.`,
    sshguard_blocking: `<38>1 2026-02-15T22:27:37.012592+01:00 pfSense.lohdal.com sshguard 6554 - - Blocking "192.168.178.58/32" for 120 secs (3 attacks in 22 secs, after 1 abuses over 22 secs.)`,
    phpfpm_auth_failure: `<32>1 2026-02-15T22:27:37.010961+01:00 pfSense.lohdal.com php-fpm 39332 - - /index.php: webConfigurator authentication error for user 'slp' from: 192.168.178.58`,
    phpfpm_auth_success: `<32>1 2026-02-15T22:28:42.123456+01:00 pfSense.lohdal.com php-fpm 39332 - - /index.php: webConfigurator login for user 'admin' from: 192.168.178.100`
};

// Sample Logstash configuration for pfSense
const sampleConfig = `filter {
  # Parse syslog header
  grok {
    match => { "message" => "<%{POSINT:syslog_pri}>%{NONNEGINT:syslog_version} %{TIMESTAMP_ISO8601:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{SYSLOGPROG:syslog_program} %{POSINT:syslog_pid} - - %{GREEDYDATA:syslog_message}" }
  }

  # Parse pfSense filterlog
  if [syslog_program] == "filterlog" {
    csv {
      source => "syslog_message"
      columns => ["rule_num","sub_rule","anchor","tracker","interface","reason","action","direction","ip_version","tos","ecn","ttl","id","offset","flags","proto_id","proto","length","src_ip","dst_ip","src_port","dst_port","data_length","tcp_flags","sequence","ack","window","urg","options"]
    }
    
    mutate {
      add_field => { "event_type" => "firewall" }
      convert => {
        "src_port" => "integer"
        "dst_port" => "integer"
        "rule_num" => "integer"
      }
    }
  }

  # Parse DHCP logs
  if [syslog_program] == "dhcpd" {
    grok {
      match => { "syslog_message" => "DHCP%{WORD:dhcp_action} on %{IP:dhcp_ip} to %{MAC:dhcp_mac}( \\(%{DATA:dhcp_hostname}\\))?" }
    }
    mutate {
      add_field => { "event_type" => "dhcp" }
    }
  }

  # Parse OpenVPN logs
  if [syslog_program] =~ /^openvpn/ {
    grok {
      match => { "syslog_message" => "%{IP:vpn_client_ip}:%{POSINT:vpn_client_port} \\[%{DATA:vpn_client_name}\\] %{GREEDYDATA:vpn_message}" }
    }
    mutate {
      add_field => { "event_type" => "vpn" }
    }
  }

  # Parse timestamp
  date {
    match => [ "syslog_timestamp", "ISO8601" ]
    target => "@timestamp"
  }

  # Add GeoIP information for source IP
  geoip {
    source => "src_ip"
  }
}`;

// Make showConfigModal global
window.showConfigModal = function(filterType, config, line) {
    const modal = document.getElementById('configModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalConfig = document.getElementById('modalConfig');
    
    modalTitle.textContent = `${filterType} Filter Configuration (line ${line})`;
    
    // Split config into lines and wrap each in a span for line numbering
    const lines = config.split('\n');
    const numberedLines = lines.map(line => `<span class="line">${escapeHtml(line)}</span>`).join('\n');
    modalConfig.innerHTML = numberedLines;
    
    modal.style.display = 'block';
};

// DOM Elements
const configFileInput = document.getElementById('logstash-config');
const configTextarea = document.getElementById('config-text');
const logEntryTextarea = document.getElementById('log-entry');
const parseBtn = document.getElementById('parse-btn');
const resultsContainer = document.getElementById('results-container');
const configChainContainer = document.getElementById('config-chain-container');
const addConfigBtn = document.getElementById('add-config-btn');
const addPastedConfigBtn = document.getElementById('add-pasted-config');
// Input stream UI removed - using auto-detection
// const inputStreamsContainer = document.getElementById('input-streams-container');
// const addInputStreamBtn = document.getElementById('add-input-stream-btn');
// Input stream selector removed - using auto-detection instead
// const inputStreamSelector = document.getElementById('input-stream-selector');
const exportJsonBtn = document.getElementById('export-json-btn');
const showStructureBtn = document.getElementById('show-structure-btn');
// const extractInputsBtn = document.getElementById('extract-inputs-btn'); // Removed - no longer needed
const structureModal = document.getElementById('structure-modal');
const structureTree = document.getElementById('structure-tree');

// Modal close handlers - use event delegation
const configModal = document.getElementById('configModal');

// Close on X button click
document.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-close')) {
        configModal.style.display = 'none';
    }
});

// Close on outside click
window.addEventListener('click', (e) => {
    if (e.target === configModal) {
        configModal.style.display = 'none';
    }
});

// Close on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && configModal && configModal.style.display === 'block') {
        configModal.style.display = 'none';
    }
});

// Store parsing structure
let lastParsingStructure = null;

// Logging system
const Logger = {
    enabled: true,
    
    log: function(category, message, data) {
        if (!this.enabled) return;
        const timestamp = new Date().toISOString().split('T')[1].slice(0, 12);
        console.log(`[${timestamp}] [${category}]`, message, data || '');
    },
    
    debug: function(message, data) {
        this.log('DEBUG', message, data);
    },
    
    info: function(message, data) {
        this.log('INFO', message, data);
    },
    
    warn: function(message, data) {
        this.log('WARN', message, data);
    },
    
    error: function(message, data) {
        this.log('ERROR', message, data);
    },
    
    structure: function(message, data) {
        this.log('STRUCTURE', message, data);
    },
    
    enable: function() {
        this.enabled = true;
        console.log('%c📊 Logging enabled', 'color: #10b981; font-weight: bold');
    },
    
    disable: function() {
        this.enabled = false;
    }
};

// Enable logging by default (can be disabled with Logger.disable() in console)
Logger.enable();

// Event Listeners
configFileInput.addEventListener('change', handleConfigFileUpload);
addConfigBtn.addEventListener('click', () => configFileInput.click());
addPastedConfigBtn.addEventListener('click', handleAddPastedConfig);
// addInputStreamBtn removed - using auto-detection
exportJsonBtn.addEventListener('click', handleExportJson);
showStructureBtn.addEventListener('click', showStructureModal);
// extractInputsBtn removed - no longer needed with auto-detection
document.querySelectorAll('.sample-btn').forEach(btn => {
    btn.addEventListener('click', handleSampleClick);
});
document.querySelectorAll('.sample-config-btn').forEach(btn => {
    btn.addEventListener('click', handleSampleConfigClick);
});
parseBtn.addEventListener('click', handleParse);

// Modal close handlers
document.querySelector('.modal-close').addEventListener('click', closeStructureModal);
window.addEventListener('click', (e) => {
    if (e.target === structureModal) {
        closeStructureModal();
    }
});

// Don't auto-load sample config - user can click the button to load it
renderConfigChain();

// Note: Input streams removed - using auto-detection from log content
// The 00-input.pfelk config handles actual input configuration in Logstash

/**
 * Handle config file upload (now supports multiple files)
 */
function handleConfigFileUpload(e) {
    const files = Array.from(e.target.files);
    if (files.length === 0) return;

    files.forEach(file => {
        const reader = new FileReader();
        reader.onload = (event) => {
            addConfigToChain(file.name, event.target.result);
            renderConfigChain();
            // Auto-extract input sources after adding config
            extractInputsFromConfig();
        };
        reader.readAsText(file);
    });

    // Reset input so same file can be added again
    e.target.value = '';
}

/**
 * Handle adding pasted config
 */
function handleAddPastedConfig() {
    const configText = configTextarea.value.trim();
    if (!configText) {
        alert('Please paste a configuration first');
        return;
    }

    const name = prompt('Enter a name for this configuration:', `Config ${configChain.length + 1}`);
    if (name) {
        addConfigToChain(name, configText);
        renderConfigChain();
        configTextarea.value = ''; // Clear textarea
        // Auto-extract input sources after adding config
        extractInputsFromConfig();
    }
}

/**
 * Add config to chain
 */
function addConfigToChain(name, content) {
    configChain.push({
        id: Date.now() + Math.random(),
        name: name,
        content: content
    });
    
    // Sort configs numerically if they start with numbers
    sortConfigChain();
    
    // Note: extractInputsBtn removed - using auto-detection
}

/**
 * Sort config chain numerically by filename prefix
 */
function sortConfigChain() {
    configChain.sort((a, b) => {
        // Extract leading numbers from filenames
        const aMatch = a.name.match(/^(\d+)/);
        const bMatch = b.name.match(/^(\d+)/);
        
        // Both have numbers - sort numerically
        if (aMatch && bMatch) {
            return parseInt(aMatch[1]) - parseInt(bMatch[1]);
        }
        
        // Only a has number - it comes first
        if (aMatch) return -1;
        
        // Only b has number - it comes first
        if (bMatch) return 1;
        
        // Neither has number - sort alphabetically
        return a.name.localeCompare(b.name);
    });
}

/**
 * Remove config from chain
 */
function removeConfigFromChain(id) {
    configChain = configChain.filter(config => config.id !== id);
    renderConfigChain();
    
    // Auto-extract input sources after removing config
    extractInputsFromConfig();
    
    // Note: extractInputsBtn removed - using auto-detection
}

/**
 * Move config up in chain
 */
function moveConfigUp(id) {
    const index = configChain.findIndex(c => c.id === id);
    if (index > 0) {
        [configChain[index], configChain[index - 1]] = [configChain[index - 1], configChain[index]];
        renderConfigChain();
    }
}

/**
 * Move config down in chain
 */
function moveConfigDown(id) {
    const index = configChain.findIndex(c => c.id === id);
    if (index < configChain.length - 1) {
        [configChain[index], configChain[index + 1]] = [configChain[index + 1], configChain[index]];
        renderConfigChain();
    }
}

/**
 * Render config chain
 */
function renderConfigChain() {
    if (configChain.length === 0) {
        configChainContainer.innerHTML = '<div class="empty-chain-message">No configurations loaded. Upload files or paste configuration above.</div>';
        return;
    }

    configChainContainer.innerHTML = '';
    
    configChain.forEach((config, index) => {
        const item = document.createElement('div');
        item.className = 'config-chain-item';
        
        const previewId = `config-preview-${config.id}`;
        
        item.innerHTML = `
            <div class="config-chain-header">
                <div class="config-order">${index + 1}</div>
                <div class="config-name">${escapeHtml(config.name)}</div>
                <div class="config-actions">
                    ${index > 0 ? `<button class="config-action-btn" onclick="moveConfigUp(${config.id})" title="Move up">⬆️</button>` : ''}
                    ${index < configChain.length - 1 ? `<button class="config-action-btn" onclick="moveConfigDown(${config.id})" title="Move down">⬇️</button>` : ''}
                    <button class="config-action-btn config-toggle-preview" onclick="toggleConfigPreview('${previewId}')" title="Toggle preview">▼</button>
                    <button class="config-action-btn" onclick="removeConfigFromChain(${config.id})" title="Remove">❌</button>
                </div>
            </div>
            <div class="config-preview collapsed" id="${previewId}"><pre class="config-content-numbered">${formatConfigWithLineNumbers(config.content)}</pre></div>
            <div class="config-stats">
                <div class="config-stat">
                    <span>📝</span>
                    <span>${config.content.split('\n').length} lines</span>
                </div>
                <div class="config-stat">
                    <span>📏</span>
                    <span>${config.content.length} chars</span>
                </div>
            </div>
        `;
        
        configChainContainer.appendChild(item);
    });
}

/**
 * Toggle config preview visibility
 */
function toggleConfigPreview(previewId) {
    const preview = document.getElementById(previewId);
    const button = event.target;
    
    if (preview.classList.contains('collapsed')) {
        preview.classList.remove('collapsed');
        button.textContent = '▲';
        button.title = 'Collapse preview';
    } else {
        preview.classList.add('collapsed');
        button.textContent = '▼';
        button.title = 'Expand preview';
    }
}

/**
 * Format config content with line numbers
 */
function formatConfigWithLineNumbers(content) {
    const lines = content.split('\n');
    return lines.map(line => `<span class="line">${escapeHtml(line)}</span>`).join('\n');
}

/**
 * Highlight a specific line in a specific config view
 */
function highlightConfigLine(lineNumber, configName) {
    // Remove all existing highlights
    document.querySelectorAll('.config-content-numbered .line').forEach(line => {
        line.classList.remove('highlighted-line');
    });
    
    // If no config name provided, highlight in all configs (old behavior)
    if (!configName) {
        document.querySelectorAll('.config-content-numbered .line').forEach((line, index) => {
            if (index + 1 === lineNumber) {
                line.classList.add('highlighted-line');
                line.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        });
        return;
    }
    
    // Find the specific config card by name
    const configCards = document.querySelectorAll('.config-chain-item');
    for (const card of configCards) {
        const nameElement = card.querySelector('.config-name');
        if (nameElement && nameElement.textContent.trim() === configName) {
            // Found the right config, highlight the line within it
            const lines = card.querySelectorAll('.config-content-numbered .line');
            if (lines[lineNumber - 1]) {
                lines[lineNumber - 1].classList.add('highlighted-line');
                lines[lineNumber - 1].scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
            break;
        }
    }
}

/**
 * Handle sample log click
 */
function handleSampleClick(e) {
    const sampleType = e.target.dataset.sample;
    if (sampleLogs[sampleType]) {
        logEntryTextarea.value = sampleLogs[sampleType];
    }
}

/**
 * Handle sample config click
 */
function handleSampleConfigClick(e) {
    const configType = e.target.dataset.config;
    if (configType === 'pfsense') {
        addConfigToChain('Sample pfSense Config', sampleConfig);
        renderConfigChain();
    }
}

/**
 * Add input stream
 */
function addInputStream(name = '', type = 'syslog', port = 514, protocol = 'udp', tags = null) {
    const id = Date.now() + Math.random();
    
    // If called without parameters, show a form for user input
    if (arguments.length === 0) {
        inputStreams.push({
            id: id,
            name: `Input Stream ${inputStreams.length + 1}`,
            type: 'syslog',
            port: 514,
            protocol: 'udp',
            tags: null,
            isNew: true
        });
    } else {
        inputStreams.push({
            id: id,
            name: name,
            type: type,
            port: port,
            protocol: protocol,
            tags: tags,
            isNew: false
        });
    }
    
    renderInputStreams();
}

/**
 * Remove input stream
 */
function removeInputStream(id) {
    inputStreams = inputStreams.filter(stream => stream.id !== id);
    renderInputStreams();
}

/**
 * Update input stream
 */
function updateInputStream(id, field, value) {
    const stream = inputStreams.find(s => s.id === id);
    if (stream) {
        stream[field] = value;
        stream.isNew = false;
        renderInputStreams();
    }
}

/**
 * Render input streams
 */
function renderInputStreams() {
    if (inputStreams.length === 0) {
        inputStreamsContainer.innerHTML = '<div class="empty-streams-message">No input streams configured. Click "Add Input Stream" to define a source.</div>';
        inputStreamSelector.innerHTML = '<option value="">Select input stream (optional)</option>';
        return;
    }

    inputStreamsContainer.innerHTML = '';
    
    inputStreams.forEach((stream) => {
        const item = document.createElement('div');
        item.className = 'input-stream-item';
        
        item.innerHTML = `
            <div class="input-stream-form">
                <div class="form-group">
                    <label>Stream Name</label>
                    <input type="text" 
                           value="${escapeHtml(stream.name)}" 
                           onchange="updateInputStream(${stream.id}, 'name', this.value)"
                           placeholder="e.g., pfSense Firewall">
                </div>
                <div class="form-group">
                    <label>Type</label>
                    <select onchange="updateInputStream(${stream.id}, 'type', this.value)">
                        <option value="syslog" ${stream.type === 'syslog' ? 'selected' : ''}>Syslog</option>
                        <option value="beats" ${stream.type === 'beats' ? 'selected' : ''}>Beats</option>
                        <option value="tcp" ${stream.type === 'tcp' ? 'selected' : ''}>TCP</option>
                        <option value="udp" ${stream.type === 'udp' ? 'selected' : ''}>UDP</option>
                        <option value="http" ${stream.type === 'http' ? 'selected' : ''}>HTTP</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Port</label>
                    <input type="number" 
                           value="${stream.port}" 
                           onchange="updateInputStream(${stream.id}, 'port', parseInt(this.value))"
                           min="1" 
                           max="65535"
                           placeholder="514">
                </div>
                <div class="form-group">
                    <label>Protocol</label>
                    <select onchange="updateInputStream(${stream.id}, 'protocol', this.value)">
                        <option value="udp" ${stream.protocol === 'udp' ? 'selected' : ''}>UDP</option>
                        <option value="tcp" ${stream.protocol === 'tcp' ? 'selected' : ''}>TCP</option>
                    </select>
                </div>
                <button class="btn-danger" onclick="removeInputStream(${stream.id})" title="Remove">❌</button>
            </div>
        `;
        
        inputStreamsContainer.appendChild(item);
    });
    
    // Update selector dropdown
    updateInputStreamSelector();
}

/**
 * Update input stream selector dropdown (disabled - using auto-detection)
 */
function updateInputStreamSelector() {
    // No longer needed - using auto-detection instead
    return;
}

/**
 * Handle parse button click - uses Flask backend API
 */
async function handleParse() {
    const logEntry = logEntryTextarea.value.trim();

    if (configChain.length === 0) {
        showError('Please add at least one Logstash configuration to the pipeline');
        return;
    }

    if (!logEntry) {
        showError('Please provide a log entry to parse');
        return;
    }

    try {
        // Auto-detect log type from content
        const detected = autoDetectLogType(logEntry);
        let inputStreamInfo = null;

        const hasMatchingPcapContext = selectedPcapContext && selectedPcapContext.payload === logEntry;
        
        if (hasMatchingPcapContext && selectedPcapContext.inputStream) {
            inputStreamInfo = selectedPcapContext.inputStream;
            console.log('Using PCAP-derived input stream:', inputStreamInfo.name || inputStreamInfo.type);
        } else if (detected) {
            inputStreamInfo = {
                name: detected.name,
                type: detected.type,
                port: null,
                protocol: null,
                tags: detected.tags
            };
            console.log('Auto-detected log type:', detected.name);
        }

        // Prepare request payload
        const payload = {
            logEntry: logEntry,
            configs: configChain.map(c => ({ name: c.name, content: c.content })),
            inputStream: inputStreamInfo
        };

        if (hasMatchingPcapContext && selectedPcapContext.eventSeed) {
            payload.eventSeed = selectedPcapContext.eventSeed;
        }

        // Show loading state
        parseBtn.disabled = true;
        parseBtn.textContent = 'Parsing...';
        resultsContainer.innerHTML = '<div class="placeholder"><p>⏳ Processing log entry...</p></div>';

        // Make API call to Flask backend
        const response = await fetch('/api/parse', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to parse log entry');
        }

        const result = await response.json();

        // Store result for export and structure
        lastParseResult = result;
        lastParsingStructure = result.processing;

        // Display results with tree structure
        displayResults(result, configChain.length, inputStreamInfo);
        
        // Show buttons
        exportJsonBtn.style.display = 'block';
        showStructureBtn.style.display = 'block';
        
        // Note: extractInputsBtn removed - using auto-detection

    } catch (error) {
        showError(`Error parsing configuration: ${error.message}`);
        console.error(error);
        exportJsonBtn.style.display = 'none';
    } finally {
        // Reset button state
        parseBtn.disabled = false;
        parseBtn.textContent = 'Parse Log Entry';
    }
}

/**
 * Display parsing results
 */
function displayResults(result, configCount, inputStreamInfo) {
    Logger.info('Displaying results with tree structure', result);
    
    resultsContainer.innerHTML = '';
    
    if (!result || !result.processing || !result.processing.configs) {
        resultsContainer.innerHTML = '<div class="error">No processing data received</div>';
        return;
    }
    
    // Display each config's processing steps
    result.processing.configs.forEach((configData, configIndex) => {
        const configSection = document.createElement('div');
        configSection.className = 'config-processing-section';
        
        const configId = `config-${configIndex}-${Date.now()}`;
        
        // Debug: Log tree_steps for each config
        console.log(`Config ${configIndex} (${configData.config_name}):`, {
            tree_steps_length: configData.tree_steps?.length || 0,
            tree_steps: configData.tree_steps
        });
        
        // Count fields added and modified in this config
        const fieldStats = countFieldChanges(configData.tree_steps);
        const statsText = [];
        if (fieldStats.added > 0) statsText.push(`${fieldStats.added} field${fieldStats.added > 1 ? 's' : ''} added`);
        if (fieldStats.modified > 0) statsText.push(`${fieldStats.modified} modified`);
        if (fieldStats.removed > 0) statsText.push(`${fieldStats.removed} removed`);
        if (fieldStats.tagsAdded > 0) statsText.push(`🏷️ ${fieldStats.tagsAdded} tag${fieldStats.tagsAdded > 1 ? 's' : ''} added`);
        if (fieldStats.tagsRemoved > 0) statsText.push(`🏷️ ${fieldStats.tagsRemoved} tag${fieldStats.tagsRemoved > 1 ? 's' : ''} removed`);
        const statsDisplay = statsText.length > 0 ? ` <span style="color: #666; font-size: 0.9em;">(${statsText.join(', ')})</span>` : '';
        
        configSection.innerHTML = `
            <div class="config-section-header" onclick="toggleConfigSection('${configId}')">
                <h3 style="margin: 0; display: inline-flex; align-items: center; cursor: pointer;">
                    <span class="config-toggle" id="toggle-${configId}">▶</span>
                    📄 ${escapeHtml(configData.config_name)}${statsDisplay}
                </h3>
            </div>
        `;
        
        const treeContainer = document.createElement('div');
        treeContainer.className = 'tree-processing-results collapsed';
        treeContainer.id = configId;
        treeContainer.appendChild(renderProcessingTree(configData.tree_steps, 0, configData.config_name));
        
        configSection.appendChild(treeContainer);
        resultsContainer.appendChild(configSection);
    });
    
    // Display final event
    const finalEventSection = document.createElement('div');
    finalEventSection.className = 'final-event-section';
    finalEventSection.innerHTML = `
        <h3 style="margin-top: 30px;">🎯 Final Event 
            <button class="btn-secondary" onclick="showSummaryModal(lastParseResult.processing.finalEvent)" style="margin-left: 15px;">📋 View Summary</button>
        </h3>
        <pre class="event-json">${JSON.stringify(result.processing.finalEvent, null, 2)}</pre>
    `;
    resultsContainer.appendChild(finalEventSection);
    
    // Display Elasticsearch output information only if output config is present
    if (result.output) {
        const outputSection = document.createElement('div');
        outputSection.className = 'output-section';
        
        // Extract data stream information
        const outputConfig = result.output;
        const finalEvent = result.processing.finalEvent;
        
        // Resolve namespace from metadata or config
        let namespace = outputConfig.data_stream?.namespace || "default";
        if (namespace.includes('%{')) {
            // Resolve field reference like %{[@metadata][pfelk_namespace]}
            const fieldRef = namespace.match(/%\{([^\}]+)\}/);
            if (fieldRef) {
                const fieldPath = fieldRef[1];
                const value = getNestedValue(finalEvent, fieldPath);
                if (value) namespace = value;
            }
        }
        
        const dataStreamType = outputConfig.data_stream?.type || "logs";
        const dataStreamDataset = outputConfig.data_stream?.dataset || "pfelk";
        const dataStreamName = `${dataStreamType}-${dataStreamDataset}-${namespace}`;
        
        outputSection.innerHTML = `
            <h3 style="margin-top: 30px;">📤 Elasticsearch Output</h3>
            <div class="output-card">
                <div class="output-info">
                    <h4>Data Stream Configuration</h4>
                    <div class="output-item">
                        <span class="output-label">Data Stream Name:</span>
                        <span class="output-value"><code>${escapeHtml(dataStreamName)}</code></span>
                    </div>
                    <div class="output-item">
                        <span class="output-label">Type:</span>
                        <span class="output-value"><code>${escapeHtml(dataStreamType)}</code></span>
                    </div>
                    <div class="output-item">
                        <span class="output-label">Dataset:</span>
                        <span class="output-value"><code>${escapeHtml(dataStreamDataset)}</code></span>
                    </div>
                    <div class="output-item">
                        <span class="output-label">Namespace:</span>
                        <span class="output-value"><code>${escapeHtml(namespace)}</code></span>
                    </div>
                    ${outputConfig.connection?.hosts ? `
                    <div class="output-item">
                        <span class="output-label">Elasticsearch Host:</span>
                        <span class="output-value"><code>${escapeHtml(outputConfig.connection.hosts[0])}</code></span>
                    </div>
                    ` : ''}
                    ${outputConfig.connection?.user ? `
                    <div class="output-item">
                        <span class="output-label">User:</span>
                        <span class="output-value"><code>${escapeHtml(outputConfig.connection.user)}</code></span>
                    </div>
                    ` : ''}
                    ${outputConfig.connection?.ssl_enabled !== undefined ? `
                    <div class="output-item">
                        <span class="output-label">SSL Enabled:</span>
                        <span class="output-value"><code>${outputConfig.connection.ssl_enabled ? 'Yes' : 'No'}</code></span>
                    </div>
                    ` : ''}
                    ${outputConfig.connection?.ssl_verification_mode ? `
                    <div class="output-item">
                        <span class="output-label">SSL Verification Mode:</span>
                        <span class="output-value"><code>${escapeHtml(outputConfig.connection.ssl_verification_mode)}</code></span>
                    </div>
                    ` : ''}
                    ${outputConfig.connection?.ssl_certificate_authorities ? `
                    <div class="output-item">
                        <span class="output-label">SSL Certificate Authorities:</span>
                        <span class="output-value"><code>${escapeHtml(outputConfig.connection.ssl_certificate_authorities.join(', '))}</code></span>
                    </div>
                    ` : ''}
                </div>
                <div class="output-preview">
                    <h4>Document Preview (as would be indexed)</h4>
                    <pre class="output-json">${JSON.stringify(finalEvent, null, 2)}</pre>
                </div>
            </div>
        `;
        resultsContainer.appendChild(outputSection);
    }
    
    // Show summary modal automatically
    showSummaryModal(result.processing.finalEvent);
    
    // Store for export
    lastParsingResult = result;
}

/**
 * Count field changes in processing tree
 */
function countFieldChanges(steps) {
    let added = 0;
    let modified = 0;
    let removed = 0;
    let tagsAdded = 0;
    let tagsRemoved = 0;
    
    function traverseSteps(stepList) {
        if (!stepList) return;
        
        stepList.forEach(step => {
            // Count fields from filter steps
            if (step.type === 'filter') {
                if (step.fields_added) added += step.fields_added.length;
                if (step.fields_modified) modified += step.fields_modified.length;
                if (step.fields_removed) removed += step.fields_removed.length;
                if (step.tags_added) tagsAdded += step.tags_added.length;
                if (step.tags_removed) tagsRemoved += step.tags_removed.length;
            }
            
            // Recursively process children
            if (step.children) {
                traverseSteps(step.children);
            }
        });
    }
    
    traverseSteps(steps);
    return { added, modified, removed, tagsAdded, tagsRemoved };
}

/**
 * Render processing tree recursively
 */
function renderProcessingTree(steps, depth, configName) {
    const container = document.createElement('div');
    container.className = 'processing-tree-level';
    
    if (!steps || steps.length === 0) {
        return container;
    }
    
    steps.forEach((step, index) => {
        const stepDiv = document.createElement('div');
        stepDiv.className = `processing-step depth-${depth}`;
        stepDiv.style.marginLeft = `${depth * 20}px`;
        
        if (step.type === 'conditional') {
            stepDiv.classList.add('conditional-step');
            if (step.skipped) stepDiv.classList.add('skipped');
            if (step.matched) stepDiv.classList.add('matched');
            
            const conditionText = step.condition_type === 'else' ? 'else' : 
                                 step.condition_type === 'else_if' ? `else if ${step.condition}` :
                                 `if ${step.condition}`;
            
            const condId = `cond-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
            
            stepDiv.innerHTML = `
                <div class="step-header conditional-header ${step.matched ? 'matched' : 'not-matched'}" data-line="${step.line}" onclick="highlightConfigLine(${step.line}, '${escapeHtml(configName)}')" style="cursor: pointer;">
                    <div class="step-icon">🔀</div>
                    <div class="step-info">
                        <div class="step-title">${escapeHtml(conditionText)}</div>
                        <div class="step-meta">
                            <span class="step-line">line ${step.line}</span>
                            <span class="step-status ${step.matched ? 'status-matched' : 'status-skipped'}">
                                ${step.matched ? '✓ Matched' : '✗ Not Matched'}
                            </span>
                        </div>
                    </div>
                    <button class="step-toggle" data-target="${condId}" onclick="event.stopPropagation();">▶</button>
                </div>
                <div class="step-details collapsed" id="${condId}">
                    ${step.event_before ? `
                        <div class="event-comparison">
                            <div class="event-col">
                                <h4>Event Before:</h4>
                                <pre>${JSON.stringify(step.event_before, null, 2)}</pre>
                            </div>
                        </div>
                    ` : ''}
                    <div class="children-container"></div>
                </div>
            `;
            
            // Add children
            if (step.children && step.children.length > 0) {
                const childrenContainer = stepDiv.querySelector('.children-container');
                const childrenTree = renderProcessingTree(step.children, depth + 1, configName);
                childrenContainer.appendChild(childrenTree);
                
                // Add toggle functionality
                const toggleBtn = stepDiv.querySelector('.step-toggle');
                const detailsDiv = stepDiv.querySelector('.step-details');
                if (toggleBtn) {
                    toggleBtn.addEventListener('click', function() {
                        detailsDiv.classList.toggle('collapsed');
                        this.textContent = detailsDiv.classList.contains('collapsed') ? '▶' : '▼';
                    });
                }
            }
            
        } else if (step.type === 'filter') {
            stepDiv.classList.add('filter-step');
            if (step.skipped) stepDiv.classList.add('skipped');
            
            const hasChanges = step.fields_added && step.fields_added.length > 0 || 
                             step.fields_modified && step.fields_modified.length > 0 ||
                             step.fields_removed && step.fields_removed.length > 0 ||
                             step.tags_added && step.tags_added.length > 0 ||
                             step.tags_removed && step.tags_removed.length > 0;
            
            // Build status text
            let statusParts = [];
            if (step.fields_added && step.fields_added.length > 0) statusParts.push(`${step.fields_added.length} field${step.fields_added.length > 1 ? 's' : ''} added`);
            if (step.fields_modified && step.fields_modified.length > 0) statusParts.push(`${step.fields_modified.length} modified`);
            if (step.fields_removed && step.fields_removed.length > 0) statusParts.push(`${step.fields_removed.length} removed`);
            if (step.tags_added && step.tags_added.length > 0) statusParts.push(`🏷️ ${step.tags_added.length} tag${step.tags_added.length > 1 ? 's' : ''} added`);
            if (step.tags_removed && step.tags_removed.length > 0) statusParts.push(`🏷️ ${step.tags_removed.length} tag${step.tags_removed.length > 1 ? 's' : ''} removed`);
            const statusText = statusParts.length > 0 ? statusParts.join(', ') : 'No Changes';
            
            // Debug log for mutate filters
            if (step.filter_type === 'mutate') {
                console.log('Mutate step data:', {
                    fields_added: step.fields_added,
                    fields_modified: step.fields_modified,
                    fields_removed: step.fields_removed,
                    tags_added: step.tags_added,
                    tags_removed: step.tags_removed
                });
            }
            
            const stepId = `step-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
            const configId = `config-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
            
            stepDiv.innerHTML = `
                <div class="step-header filter-header ${step.skipped ? 'skipped' : ''}" data-line="${step.line}" onclick="highlightConfigLine(${step.line}, '${escapeHtml(configName)}')" style="cursor: pointer;">
                    <div class="step-icon">⚙️</div>
                    <div class="step-info">
                        <div class="step-title">${escapeHtml(step.filter_type)}</div>
                        <div class="step-meta">
                            <span class="step-line">line ${step.line}</span>
                            <span class="step-status ${step.skipped ? 'status-skipped' : hasChanges ? 'status-changed' : 'status-unchanged'}">
                                ${step.skipped ? 'Skipped' : statusText}
                            </span>
                        </div>
                    </div>
                    <div class="step-actions">
                        <button class="config-button" data-config-id="${configId}" title="View Configuration" onclick="event.stopPropagation();">📝</button>
                        ${!step.skipped ? `<button class="step-toggle" data-target="${stepId}" onclick="event.stopPropagation();">▶</button>` : ''}
                    </div>
                </div>
                ${!step.skipped ? `
                    <div class="step-details collapsed" id="${stepId}">
                        <div class="event-comparison">
                            <div class="event-col">
                                <h4>Event Before:</h4>
                                <pre>${JSON.stringify(step.event_before, null, 2)}</pre>
                            </div>
                            <div class="event-col">
                                <h4>Event After:</h4>
                                <pre>${JSON.stringify(step.event_after, null, 2)}</pre>
                            </div>
                        </div>
                        ${step.fields_added && step.fields_added.length > 0 ? `
                            <div class="changes-section">
                                <h4>Fields Added:</h4>
                                <ul>${step.fields_added.map(f => `<li><code>${escapeHtml(f)}</code></li>`).join('')}</ul>
                            </div>
                        ` : ''}
                        ${step.fields_modified && step.fields_modified.length > 0 ? `
                            <div class="changes-section">
                                <h4>Fields Modified:</h4>
                                <ul>${step.fields_modified.map(f => `<li><code>${escapeHtml(f)}</code></li>`).join('')}</ul>
                            </div>
                        ` : ''}
                        ${step.fields_removed && step.fields_removed.length > 0 ? `
                            <div class="changes-section">
                                <h4>Fields Removed:</h4>
                                <ul>${step.fields_removed.map(f => `<li><code>${escapeHtml(f)}</code></li>`).join('')}</ul>
                            </div>
                        ` : ''}
                        ${step.tags_added && step.tags_added.length > 0 ? `
                            <div class="changes-section">
                                <h4>Tags Added:</h4>
                                <ul>${step.tags_added.map(t => `<li><span class="tag-badge">🏷️ ${escapeHtml(t)}</span></li>`).join('')}</ul>
                            </div>
                        ` : ''}
                        ${step.tags_removed && step.tags_removed.length > 0 ? `
                            <div class="changes-section">
                                <h4>Tags Removed:</h4>
                                <ul>${step.tags_removed.map(t => `<li><span class="tag-badge-removed">🏷️ ${escapeHtml(t)}</span></li>`).join('')}</ul>
                            </div>
                        ` : ''}
                    </div>
                ` : ''}
            `;
            
            // Store config in a data attribute
            stepDiv.dataset.config = step.config || '';
            stepDiv.dataset.configId = configId;
            
            // Add config button functionality
            const configBtn = stepDiv.querySelector('.config-button');
            if (configBtn) {
                configBtn.addEventListener('click', function(e) {
                    e.stopPropagation();
                    showConfigModal(step.filter_type, step.config || 'No configuration available', step.line);
                });
            }
            
            // Add toggle functionality
            const toggleBtn = stepDiv.querySelector('.step-toggle');
            if (toggleBtn) {
                toggleBtn.addEventListener('click', function() {
                    const targetId = this.getAttribute('data-target');
                    const details = document.getElementById(targetId);
                    if (details) {
                        details.classList.toggle('collapsed');
                        this.textContent = details.classList.contains('collapsed') ? '▶' : '▼';
                    }
                });
            }
        }
        
        container.appendChild(stepDiv);
    });
    
    return container;
}

/**
 * Create summary section
 */
function createSummarySection(result, configCount, inputStreamInfo) {
    const summary = document.createElement('div');
    summary.className = 'summary-section';

    const totalSteps = result.steps.length - 1; // Exclude initial step
    const successSteps = result.steps.filter(s => s.success !== false).length - 1;
    const totalFields = Object.keys(result.finalData).length;

    const inputStreamHTML = inputStreamInfo ? `
        <div class="stat-item">
            <div class="stat-value">📡</div>
            <div class="stat-label">${escapeHtml(inputStreamInfo.name)}<br>
            <small>${inputStreamInfo.type}:${inputStreamInfo.port}/${inputStreamInfo.protocol.toUpperCase()}</small></div>
        </div>
    ` : '';

    summary.innerHTML = `
        <div class="summary-title">📊 Parsing Summary</div>
        <div class="summary-stats">
            ${inputStreamHTML}
            <div class="stat-item">
                <div class="stat-value">${configCount || 1}</div>
                <div class="stat-label">Config Files</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">${totalSteps}</div>
                <div class="stat-label">Filter Steps</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">${successSteps}</div>
                <div class="stat-label">Successful</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">${totalFields}</div>
                <div class="stat-label">Fields Extracted</div>
            </div>
        </div>
    `;

    return summary;
}

/**
 * Create step element
 */
function createStepElement(step) {
    const stepDiv = document.createElement('div');
    stepDiv.className = 'pipeline-step';
    
    if (step.skipped) {
        stepDiv.className += ' skipped-step';
    }

    const statusBadge = step.skipped
        ? '<span class="status-badge status-warning">Skipped</span>'
        : step.success === false 
            ? '<span class="status-badge status-error">Error</span>'
            : step.newFields && step.newFields.length > 0 
                ? '<span class="status-badge status-success">Fields Added</span>'
                : '<span class="status-badge status-warning">No Changes</span>';

    const configBadge = step.configName 
        ? `<span class="config-source-badge" title="From configuration: ${escapeHtml(step.configName)}">${escapeHtml(step.configName)}</span>`
        : '';

    const inputBadge = step.inputStream 
        ? `<span class="input-info-badge" title="Input stream: ${escapeHtml(step.inputStream.name)}">📡 ${step.inputStream.type}:${step.inputStream.port}/${step.inputStream.protocol.toUpperCase()}</span>`
        : '';

    stepDiv.innerHTML = `
        <div class="step-header" onclick="toggleStep(this)">
            <div class="step-number">${step.step}</div>
            <div class="step-title">
                ${step.step === 0 ? '📥 Input' : `🔧 ${step.filterType}`}
                ${inputBadge}
                ${configBadge}
                ${statusBadge}
            </div>
            <div class="step-toggle">▼</div>
        </div>
        <div class="step-content">
            ${createStepContent(step)}
        </div>
    `;

    return stepDiv;
}

/**
 * Create step content
 */
function createStepContent(step) {
    let content = '';

    // Add condition info if present
    if (step.condition) {
        const conditionClass = step.skipped ? 'condition-failed' : 'condition-met';
        const conditionIcon = step.skipped ? '❌' : '✅';
        const conditionText = step.skipped ? 'Condition NOT met - Filter skipped' : 'Condition met - Filter applied';
        
        content += `<div class="filter-info ${conditionClass}">
            <div class="filter-type">${conditionIcon} ${conditionText}</div>
            <div class="filter-config">if ${escapeHtml(step.condition.original)}</div>
        </div>`;
    }

    // Add description
    if (step.description && !step.skipped) {
        content += `<div class="filter-info">
            <div class="filter-type">${step.description}</div>
        </div>`;
    }

    // Add filter configuration
    if (step.filterConfig && !step.skipped) {
        content += `<div class="filter-info">
            <div class="filter-type">Configuration:</div>
            <div class="filter-config">${escapeHtml(step.filterConfig)}</div>
        </div>`;
    }

    // Add error if present
    if (step.error) {
        content += `<div class="error-message">
            <strong>Error:</strong> ${escapeHtml(step.error)}
        </div>`;
    }

    // Add fields (even for skipped steps to show unchanged state)
    if (!step.skipped) {
        content += createFieldsSection(step);
    } else {
        content += `<div class="fields-container">
            <div class="fields-title">Fields unchanged (filter was skipped)</div>
        </div>`;
    }

    return content;
}

/**
 * Create fields section
 */
function createFieldsSection(step) {
    const fieldCount = Object.keys(step.fields).length;
    
    let html = `
        <div class="fields-container">
            <div class="fields-title">
                Extracted Fields
                <span class="field-count">${fieldCount}</span>
            </div>
            <div class="field-list">
    `;

    Object.entries(step.fields).forEach(([name, value]) => {
        let fieldClass = 'field-item';
        
        if (step.newFields && step.newFields.includes(name)) {
            fieldClass += ' field-added';
        } else if (step.modifiedFields && step.modifiedFields.includes(name)) {
            fieldClass += ' field-modified';
        }

        // Format value display
        let displayValue;
        if (Array.isArray(value)) {
            displayValue = '[' + value.map(v => JSON.stringify(v)).join(', ') + ']';
        } else if (typeof value === 'object' && value !== null) {
            displayValue = JSON.stringify(value, null, 2);
        } else {
            displayValue = String(value);
        }

        html += `
            <div class="${fieldClass}">
                <div class="field-name">${escapeHtml(name)}</div>
                <div class="field-value">${escapeHtml(displayValue)}</div>
            </div>
        `;
    });

    // Show removed fields
    if (step.removedFields && step.removedFields.length > 0) {
        step.removedFields.forEach(name => {
            html += `
                <div class="field-item field-removed">
                    <div class="field-name">${escapeHtml(name)}</div>
                    <div class="field-value">(removed)</div>
                </div>
            `;
        });
    }

    html += `
            </div>
        </div>
    `;

    return html;
}

/**
 * Toggle step visibility
 */
function toggleStep(header) {
    const content = header.nextElementSibling;
    const toggle = header.querySelector('.step-toggle');
    
    content.classList.toggle('collapsed');
    toggle.classList.toggle('collapsed');
}

/**
 * Show error message
 */
function showError(message) {
    resultsContainer.innerHTML = `
        <div class="error-message">
            <strong>⚠️ Error:</strong> ${escapeHtml(message)}
        </div>
    `;
    exportJsonBtn.style.display = 'none';
    showStructureBtn.style.display = 'none';
}

/**
 * Escape HTML
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Get nested value from object using field path like [@metadata][pfelk_namespace]
 */
function getNestedValue(obj, path) {
    // Remove leading @ if present and split by ][
    const cleanPath = path.replace(/^@/, '').replace(/^\[/, '').replace(/\]$/, '');
    const parts = cleanPath.split('][');
    
    let current = obj;
    for (const part of parts) {
        if (current && typeof current === 'object' && part in current) {
            current = current[part];
        } else {
            return null;
        }
    }
    return current;
}

/**
 * Handle export to JSON
 */
function handleExportJson() {
    if (!lastParseResult) {
        alert('No parsing results to export');
        return;
    }

    try {
        // Create JSON string with pretty formatting
        const jsonString = JSON.stringify(lastParseResult, null, 2);
        
        // Create blob and download
        const blob = new Blob([jsonString], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        
        // Generate filename with timestamp
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
        a.download = `logstash-parse-result-${timestamp}.json`;
        
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (error) {
        alert('Error exporting JSON: ' + error.message);
        console.error(error);
    }
}

/**
 * Extract input sources from config files
 */
function extractInputsFromConfig() {
    Logger.info('=== Extracting inputs from configs ===');
    
    if (!configChain || configChain.length === 0) {
        alert('No configuration files loaded');
        return;
    }
    
    // Note: Input stream UI removed - auto-detection is used instead
    // The 00-input.pfelk config defines the actual input sources for Logstash
    
    let totalInputsFound = 0;
    
    configChain.forEach((config, configIndex) => {
        const inputs = extractInputBlocks(config.content);
        Logger.info(`Config ${configIndex + 1} (${config.name}): Found ${inputs.length} input sources`);
        totalInputsFound += inputs.length;
    });
    
    // Silent success - no popup
    Logger.info(`Extracted ${totalInputsFound} input source(s) from configuration files`);
}

/**
 * Extract input blocks from config text
 */
function extractInputBlocks(configText) {
    Logger.structure('=== Extracting input blocks ===');
    const inputs = [];
    const lines = configText.split('\n');
    let inInputBlock = false;
    let depth = 0;
    let currentInput = null;
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        
        if (!trimmed || trimmed.startsWith('#')) continue;
        
        // Check if we're entering the input block
        if (trimmed.match(/^input\s*\{/)) {
            inInputBlock = true;
            depth = 0;
            Logger.debug('Found input block start');
            continue;
        }
        
        // Only process lines inside the input block
        if (!inInputBlock) continue;
        
        // Count braces (excluding escaped ones)
        const openBraces = (line.replace(/\\[{}]/g, '').match(/\{/g) || []).length;
        const closeBraces = (line.replace(/\\[{}]/g, '').match(/\}/g) || []).length;
        
        // Check for input types (tcp, udp, syslog, etc.)
        if (trimmed.match(/^(tcp|udp|syslog|file|stdin|beats|http)\s*\{/)) {
            const protocol = trimmed.match(/^(\w+)\s*\{/)[1];
            currentInput = {
                protocol: protocol,
                type: '',
                port: 0,
                tags: [],
                id: '',
                lineStart: i + 1
            };
            Logger.structure(`Found ${protocol} input at line ${i + 1}`);
        }
        
        // Extract properties if we're inside an input definition
        if (currentInput && depth > 0) {
            // Extract type
            const typeMatch = trimmed.match(/type\s*=>\s*"([^"]+)"/);
            if (typeMatch) {
                currentInput.type = typeMatch[1];
                Logger.debug(`  type: ${currentInput.type}`);
            }
            
            // Extract port
            const portMatch = trimmed.match(/port\s*=>\s*(\d+)/);
            if (portMatch) {
                currentInput.port = parseInt(portMatch[1]);
                Logger.debug(`  port: ${currentInput.port}`);
            }
            
            // Extract tags
            const tagsMatch = trimmed.match(/tags\s*=>\s*\[(.*?)\]/);
            if (tagsMatch) {
                const tagsStr = tagsMatch[1];
                currentInput.tags = tagsStr.split(',').map(t => t.trim().replace(/"/g, ''));
                Logger.debug(`  tags: ${currentInput.tags.join(', ')}`);
            }
            
            // Extract id
            const idMatch = trimmed.match(/id\s*=>\s*"([^"]+)"/);
            if (idMatch) {
                currentInput.id = idMatch[1];
                Logger.debug(`  id: ${currentInput.id}`);
            }
        }
        
        // Adjust depth
        depth += openBraces;
        depth -= closeBraces;
        
        // If we close an input definition, save it
        if (currentInput && depth === 0 && closeBraces > 0) {
            inputs.push(currentInput);
            Logger.structure(`Completed input extraction:`, currentInput);
            currentInput = null;
        }
        
        // Exit input block
        if (depth < 0 && inInputBlock) {
            Logger.debug('Exited input block');
            break;
        }
    }
    
    Logger.structure(`=== Input extraction complete: ${inputs.length} inputs found ===`);
    return inputs;
}

/**
 * Add input stream from extracted data
 */
function addInputStreamFromExtraction(input, configName) {
    const streamId = `stream-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    // Determine display name
    let displayName = input.type || input.protocol;
    if (input.port) {
        displayName += ` (${input.protocol.toUpperCase()}:${input.port})`;
    }
    if (input.id) {
        displayName = input.id;
    }
    
    const streamDiv = document.createElement('div');
    streamDiv.className = 'input-stream-item';
    streamDiv.dataset.streamId = streamId;
    
    streamDiv.innerHTML = `
        <div class="stream-header">
            <span class="stream-name">📡 ${escapeHtml(displayName)}</span>
            <span class="stream-source">from ${escapeHtml(configName)}</span>
            <button class="btn-remove" onclick="removeInputStream('${streamId}')">✕</button>
        </div>
        <div class="stream-details">
            <span><strong>Protocol:</strong> ${input.protocol.toUpperCase()}</span>
            ${input.port ? `<span><strong>Port:</strong> ${input.port}</span>` : ''}
            ${input.type ? `<span><strong>Type:</strong> ${escapeHtml(input.type)}</span>` : ''}
            ${input.tags.length > 0 ? `<span><strong>Tags:</strong> ${input.tags.map(t => escapeHtml(t)).join(', ')}</span>` : ''}
        </div>
    `;
    
    inputStreamsContainer.appendChild(streamDiv);
    
    // Add to streams array
    inputStreams.push({
        id: streamId,
        protocol: input.protocol,
        port: input.port,
        type: input.type,
        tags: input.tags
    });
    
    // Add to selector
    const option = document.createElement('option');
    option.value = streamId;
    option.textContent = displayName;
    inputStreamSelector.appendChild(option);
    
    Logger.info(`Added input stream: ${displayName}`, input);
}

/**
 * Show structure modal
 */
function showStructureModal() {
    Logger.info('=== Opening Structure Modal ===');
    
    if (!configChain || configChain.length === 0) {
        alert('No configuration structure to display');
        return;
    }

    // Build structure tree HTML
    let html = '<div class="structure-info"><p><strong>Configuration Files:</strong> ' + configChain.length + '</p></div>';
    
    configChain.forEach((config, index) => {
        Logger.info(`Processing config ${index + 1}: ${config.name}`);
        
        html += `
            <div class="tree-node conditional" style="margin-top: 20px;">
                <div class="tree-label">📄 Config ${index + 1}: ${escapeHtml(config.name)}</div>
            </div>
        `;
        
        // Parse the config to show structure
        const filters = extractFiltersFromConfig(config.content);
        Logger.info(`Config ${index + 1} extracted ${filters.length} filters`);
        
        html += buildNestedStructureTree(filters);
    });

    structureTree.innerHTML = html;
    structureModal.style.display = 'block';
    
    Logger.info('=== Structure Modal Opened ===');
}

/**
 * Close structure modal
 */
function closeStructureModal() {
    structureModal.style.display = 'none';
}

/**
 * Extract filters from config text (simplified)
 */
function extractFiltersFromConfig(configText) {
    Logger.structure('=== Starting filter extraction ===');
    const filters = [];
    const lines = configText.split('\n');
    let depth = 0;
    let inFilterBlock = false;
    
    Logger.debug(`Total lines to process: ${lines.length}`);
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        
        if (!trimmed || trimmed.startsWith('#')) continue;
        
        // Check if we're entering the filter block
        if (trimmed.match(/^filter\s*\{/)) {
            inFilterBlock = true;
            depth = 0; // Reset depth at filter block start
            Logger.debug('Found filter block start, resetting depth to 0');
            continue;
        }
        
        // Only process lines inside the filter block
        if (!inFilterBlock) continue;
        
        // Count opening braces in this line (excluding escaped \{ and \})
        const openBraces = (line.replace(/\\[{}]/g, '').match(/\{/g) || []).length;
        // Count closing braces in this line (excluding escaped \{ and \})
        const closeBraces = (line.replace(/\\[{}]/g, '').match(/\}/g) || []).length;
        
        Logger.debug(`Line ${i + 1} (depth=${depth}): "${trimmed.substring(0, 50)}${trimmed.length > 50 ? '...' : ''}"`);
        Logger.debug(`  Braces: open=${openBraces}, close=${closeBraces}`);
        
        // Check for conditionals and filters BEFORE adjusting depth
        // Match 'if' followed by either [ or " (for array membership checks like "firewall" in [tags])
        if (trimmed.match(/^if\s+[\[\"]/) || trimmed.match(/^if\s+\[/)) {
            const condition = trimmed.match(/if\s+(.+?)\s*\{/);
            const filter = {
                type: 'conditional',
                condition: condition ? condition[1] : trimmed,
                depth: depth,
                line: i + 1
            };
            filters.push(filter);
            Logger.structure(`Found IF conditional at depth ${depth}: ${filter.condition}`, filter);
        } else if (trimmed.match(/^else\s+if\s+[\[\"]/) || trimmed.match(/^else\s+if\s+\[/)) {
            // else-if needs to be at the same level as the preceding if
            const elseIfDepth = Math.max(0, depth - 1);
            const condition = trimmed.match(/else\s+if\s+(.+?)\s*\{/);
            const filter = {
                type: 'conditional',
                condition: 'else if ' + (condition ? condition[1] : ''),
                depth: elseIfDepth,
                line: i + 1
            };
            filters.push(filter);
            Logger.structure(`Found ELSE IF conditional at depth ${elseIfDepth}: ${filter.condition}`, filter);
        } else if (trimmed.match(/^else\s*\{/)) {
            // else needs to be at the same level as the preceding if
            const elseDepth = Math.max(0, depth - 1);
            const filter = {
                type: 'conditional',
                condition: 'else',
                depth: elseDepth,
                line: i + 1
            };
            filters.push(filter);
            Logger.structure(`Found ELSE conditional at depth ${elseDepth}`, filter);
        } else if (trimmed.match(/^(grok|mutate|date|csv|json|kv|dissect|geoip|translate|cidr|dns)\s*\{/)) {
            const filterType = trimmed.match(/^(\w+)\s*\{/)[1];
            const filter = {
                type: 'filter',
                filterType: filterType,
                depth: depth,
                line: i + 1
            };
            filters.push(filter);
            Logger.structure(`Found ${filterType} filter at depth ${depth}`, filter);
        }
        
        // Now adjust depth based on braces
        const oldDepth = depth;
        depth += openBraces;
        depth -= closeBraces;
        depth = Math.max(0, depth); // Ensure non-negative
        
        if (oldDepth !== depth) {
            Logger.debug(`  Depth changed: ${oldDepth} -> ${depth}`);
        }
        
        // Check if we've exited the filter block
        // We exit when depth goes negative (closing the filter { } block itself)
        if (depth < 0 && inFilterBlock) {
            Logger.debug('Exited filter block (depth < 0)');
            break;
        }
    }
    
    Logger.structure(`=== Extraction complete: ${filters.length} filters found ===`);
    Logger.structure('Filter summary:', filters.map(f => `${f.type}(${f.filterType || f.condition}) @ depth ${f.depth}`));
    
    return filters;
}

/**
 * Build nested structure tree HTML
 */
function buildNestedStructureTree(filters) {
    if (!filters || filters.length === 0) {
        return '<div class="tree-node"><em>No filters found</em></div>';
    }
    
    return buildTreeLevel(filters, 0, 0);
}

/**
 * Build tree at a specific depth level
 */
function buildTreeLevel(filters, startIndex, currentDepth) {
    Logger.debug(`Building tree level: startIndex=${startIndex}, currentDepth=${currentDepth}, filters.length=${filters.length}`);
    
    let html = '';
    let i = startIndex;
    
    while (i < filters.length) {
        const filter = filters[i];
        
        Logger.debug(`  Processing index ${i}: ${filter.type}(${filter.filterType || filter.condition}) @ depth ${filter.depth}`);
        
        // If this filter is at a shallower depth, stop processing this level
        if (filter.depth < currentDepth) {
            Logger.debug(`  -> Stopping: filter depth ${filter.depth} < currentDepth ${currentDepth}`);
            break;
        }
        
        // If this filter is deeper, skip it (will be handled by parent's recursion)
        if (filter.depth > currentDepth) {
            Logger.debug(`  -> Skipping: filter depth ${filter.depth} > currentDepth ${currentDepth}`);
            i++;
            continue;
        }
        
        // This filter is at our current depth
        if (filter.type === 'conditional') {
            Logger.debug(`  -> Rendering conditional: ${filter.condition}`);
            html += `
                <div class="tree-node conditional" style="margin-left: ${currentDepth * 20}px;">
                    <span class="tree-label">🔀 ${escapeHtml(filter.condition)}</span>
                    <span style="color: #9ca3af; font-size: 0.9em;"> (line ${filter.line})</span>
                </div>
            `;
            
            // Find all children (depth > currentDepth) until we hit same or shallower depth
            const childStart = i + 1;
            let childEnd = childStart;
            
            while (childEnd < filters.length && filters[childEnd].depth > currentDepth) {
                childEnd++;
            }
            
            Logger.debug(`  -> Children range: ${childStart} to ${childEnd} (${childEnd - childStart} items)`);
            
            // Process children recursively - they handle their own depth filtering
            if (childEnd > childStart) {
                const childrenHtml = '<div class="tree-children">' + 
                    buildTreeLevel(filters, childStart, currentDepth + 1) + 
                    '</div>';
                html += childrenHtml;
            }
            
            // Move past this conditional only (not its children, they're already processed)
            Logger.debug(`  -> Moving index from ${i} to ${i + 1}`);
            i++;
            
        } else if (filter.type === 'filter') {
            Logger.debug(`  -> Rendering filter: ${filter.filterType}`);
            html += `
                <div class="tree-node filter" style="margin-left: ${currentDepth * 20}px;">
                    <span class="tree-label">⚙️ ${filter.filterType}</span>
                    <span style="color: #9ca3af; font-size: 0.9em;"> (line ${filter.line})</span>
                </div>
            `;
            i++;
        } else {
            i++;
        }
    }
    
    Logger.debug(`Finished tree level at depth ${currentDepth}, returning HTML length: ${html.length}`);
    return html;
}

/**
 * Build structure tree HTML (old flat version - kept for reference)
 */
function buildStructureTree(filters) {
    if (!filters || filters.length === 0) {
        return '<div class="tree-node"><em>No filters found</em></div>';
    }
    
    let html = '<div class="tree-children">';
    
    filters.forEach((filter, index) => {
        // Ensure depth is non-negative
        const safeDepth = Math.max(0, filter.depth || 0);
        const indent = '│  '.repeat(safeDepth);
        const connector = index === filters.length - 1 ? '└─ ' : '├─ ';
        
        if (filter.type === 'conditional') {
            html += `
                <div class="tree-node conditional">
                    <span class="tree-indent">${indent}${connector}</span>
                    <span class="tree-label">🔀 Conditional</span>
                    <div class="tree-condition">${escapeHtml(filter.condition)} <span style="color: #9ca3af;">(line ${filter.line})</span></div>
                </div>
            `;
        } else if (filter.type === 'filter') {
            html += `
                <div class="tree-node filter">
                    <span class="tree-indent">${indent}${connector}</span>
                    <span class="tree-label">⚙️ ${filter.filterType}</span>
                    <span style="color: #9ca3af; font-size: 0.9em;"> (line ${filter.line})</span>
                </div>
            `;
        }
    });
    
    html += '</div>';
    return html;
}

/**
 * Add MAC pattern to grok patterns (not needed in Flask version)
 */
// parser.grokPatterns.MAC = '(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}';

/**
 * Toggle config section collapse/expand
 */
function toggleConfigSection(configId) {
    const section = document.getElementById(configId);
    const toggle = document.getElementById(`toggle-${configId}`);
    
    if (section && toggle) {
        section.classList.toggle('collapsed');
        toggle.textContent = section.classList.contains('collapsed') ? '▶' : '▼';
    }
}

console.log('Logstash pfSense Parser Visualizer - Flask Edition loaded');

/**
 * Handle PCAP file upload
 */
document.getElementById('pcap-upload').addEventListener('change', async function(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    const formData = new FormData();
    formData.append('pcap', file);
    
    try {
        const response = await fetch('/api/parse_pcap', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.error) {
            alert('Error parsing PCAP: ' + data.error);
            return;
        }
        
        displayPcapLogs(data.logs, file.name);
    } catch (error) {
        alert('Error uploading PCAP: ' + error.message);
    }
    
    // Reset file input
    e.target.value = '';
});

/**
 * Display extracted logs from PCAP
 */
function displayPcapLogs(logs, filename) {
    const card = document.getElementById('pcap-logs-card');
    const infoDiv = card.querySelector('.pcap-info');
    const listDiv = document.getElementById('pcap-logs-list');
    
    infoDiv.innerHTML = `
        <strong>File:</strong> ${escapeHtml(filename)}<br>
        <strong>Logs found:</strong> ${logs.length}
    `;
    
    listDiv.innerHTML = '';
    
    logs.forEach((log, index) => {
        const logItem = document.createElement('div');
        logItem.className = 'pcap-log-item';
        
        // Detect multiple messages in payload (split by newline or RFC5424 pattern)
        const messages = detectMultipleMessages(log.payload);
        const hasMultiple = messages.length > 1;
        
        logItem.innerHTML = `
            <div class="pcap-log-header">
                <span><strong>#${index + 1}</strong>${hasMultiple ? ` <span style="color: #667eea; font-weight: bold;">(${messages.length} messages)</span>` : ''}</span>
                <span>${log.timestamp || 'No timestamp'}</span>
                <span>${log.src_ip || ''}${log.src_ip && log.dst_ip ? ' → ' : ''}${log.dst_ip || ''}</span>
            </div>
            <div class="pcap-log-content">${escapeHtml(log.payload.length > 200 ? log.payload.substring(0, 200) + '...' : log.payload)}</div>
        `;
        
        logItem.addEventListener('click', function() {
            // Deselect all
            document.querySelectorAll('.pcap-log-item').forEach(item => {
                item.classList.remove('selected');
            });
            // Select this one
            this.classList.add('selected');
            
            if (hasMultiple) {
                // Show message selection modal
                showMessageSelectionModal(messages);
                selectedPcapContext = null;
            } else {
                // Fill the log entry textarea directly
                const logEntryInput = document.getElementById('log-entry');
                logEntryInput.value = log.payload;
                selectedPcapContext = {
                    payload: log.payload,
                    inputStream: log.input_stream || null,
                    eventSeed: log.event || null
                };
                // Update auto-detected type
                updateAutoDetectedType(log.payload);
                // Scroll to the textarea
                logEntryInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        });
        
        listDiv.appendChild(logItem);
    });
    
    card.style.display = 'block';
}

/**
 * Detect multiple log messages in a payload
 */
function detectMultipleMessages(payload) {
    // Try to split by RFC5424 syslog pattern: <priority>version timestamp...
    const rfc5424Pattern = /<\d+>\d+\s+\d{4}-\d{2}-\d{2}T/g;
    const matches = [...payload.matchAll(rfc5424Pattern)];
    
    if (matches.length > 1) {
        // Found multiple RFC5424 messages
        const messages = [];
        for (let i = 0; i < matches.length; i++) {
            const start = matches[i].index;
            const end = i < matches.length - 1 ? matches[i + 1].index : payload.length;
            messages.push(payload.substring(start, end).trim());
        }
        return messages;
    }
    
    // Fallback: split by newline if there are multiple lines
    const lines = payload.split('\n').filter(line => line.trim().length > 0);
    if (lines.length > 1 && lines.every(line => line.match(/<\d+>/))) {
        // Multiple lines, each starting with syslog priority
        return lines;
    }
    
    // No multiple messages detected
    return [payload];
}

/**
 * Show message selection modal
 */
function showMessageSelectionModal(messages) {
    const modal = document.getElementById('message-selection-modal');
    const countSpan = document.getElementById('message-count');
    const listDiv = document.getElementById('message-selection-list');
    
    countSpan.textContent = messages.length;
    listDiv.innerHTML = '';
    
    messages.forEach((message, index) => {
        const item = document.createElement('div');
        item.className = 'message-selection-item';
        item.innerHTML = `
            <div class="message-selection-header">
                <span>Message #${index + 1}</span>
                <span style="font-size: 0.85em; color: #888;">${message.length} characters</span>
            </div>
            <div class="message-selection-content">${escapeHtml(message)}</div>
        `;
        
        item.addEventListener('click', function() {
            // Deselect all items
            document.querySelectorAll('.message-selection-item').forEach(i => {
                i.classList.remove('selected');
            });
            // Select this one
            this.classList.add('selected');
            
            // Fill the log entry textarea
            const logEntryInput = document.getElementById('log-entry');
            logEntryInput.value = message;
            // Update auto-detected type
            updateAutoDetectedType(message);
            // Close the modal
            closeMessageSelectionModal();
            // Scroll to the textarea
            logEntryInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
        });
        
        listDiv.appendChild(item);
    });
    
    modal.style.display = 'block';
}

/**
 * Close message selection modal
 */
function closeMessageSelectionModal() {
    document.getElementById('message-selection-modal').style.display = 'none';
}

/**
 * Close PCAP card
 */
document.getElementById('close-pcap-card').addEventListener('click', function() {
    document.getElementById('pcap-logs-card').style.display = 'none';
});

/**
 * Show summary modal after parsing
 */
function showSummaryModal(finalEvent) {
    const modal = document.getElementById('summary-modal');
    const content = document.getElementById('summary-content');
    
    // Detect log type based on event data
    const logType = detectEventLogType(finalEvent);
    
    // Generate summary based on log type
    content.innerHTML = generateSummaryContent(finalEvent, logType);
    
    modal.style.display = 'block';
}

/**
 * Detect the type of log from the parsed event
 */
function detectEventLogType(event) {
    const appname = event['log']?.['syslog']?.['appname'] || '';
    const tags = event['tags'] || [];
    
    // Check for Suricata IDS
    if (appname === 'suricata' || tags.includes('suricata') || event['suricata']) {
        return 'suricata';
    }
    
    // Check for DNS (Unbound)
    if (appname === 'unbound' || tags.includes('unbound') || event['dns']) {
        return 'dns';
    }
    
    // Check for DHCP
    if (appname.includes('dhcp') || tags.includes('dhcp')) {
        return 'dhcp';
    }
    
    // Check for OpenVPN
    if (appname === 'openvpn' || tags.includes('openvpn')) {
        return 'openvpn';
    }
    
    // Check for SSHGuard
    if (appname === 'sshguard' || tags.includes('sshguard')) {
        return 'sshguard';
    }
    
    // Check for Web Portal (php-fpm)
    if (appname === 'php-fpm' || tags.includes('web_portal') || tags.includes('authentication_failure') || tags.includes('authentication_success')) {
        return 'web_portal';
    }
    
    // Check for HAProxy
    if (appname === 'haproxy' || tags.includes('haproxy')) {
        return 'haproxy';
    }
    
    // Check for Squid
    if (appname.includes('squid') || tags.includes('squid')) {
        return 'squid';
    }
    
    // Check for firewall traffic logs
    if (appname === 'firewall' || tags.includes('firewall') || event['pf']) {
        return 'firewall';
    }
    
    // Default to system log
    return 'system';
}

/**
 * Generate summary content based on log type
 */
function generateSummaryContent(finalEvent, logType) {
    const common = {
        logType: finalEvent['log']?.['syslog']?.['appname'] || finalEvent['type'] || 'Unknown',
        hostname: finalEvent['log']?.['syslog']?.['hostname'] || 'N/A',
        timestamp: finalEvent['log']?.['syslog']?.['timestamp'] || finalEvent['@timestamp'] || 'N/A',
        tags: finalEvent['tags'] || [],
        rawMessage: finalEvent['event']?.['original'] || finalEvent['message'] || 'N/A'
    };
    
    // Add raw syslog message section at the top
    let rawMessageSection = '';
    if (common.rawMessage !== 'N/A') {
        rawMessageSection = `
            <div class="summary-section" style="grid-column: 1 / -1; margin-bottom: 20px;">
                <h3>📝 Raw Syslog Message</h3>
                <div class="summary-item" style="display: block;">
                    <pre style="background: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; margin: 0; color: #333;">${escapeHtml(common.rawMessage)}</pre>
                </div>
            </div>
        `;
    }
    
    let sections = '';
    
    switch (logType) {
        case 'firewall':
            sections = generateFirewallSummary(finalEvent, common);
            break;
        case 'suricata':
            sections = generateSuricataSummary(finalEvent, common);
            break;
        case 'dns':
            sections = generateDNSSummary(finalEvent, common);
            break;
        case 'dhcp':
            sections = generateDHCPSummary(finalEvent, common);
            break;
        case 'openvpn':
            sections = generateOpenVPNSummary(finalEvent, common);
            break;
        case 'sshguard':
            sections = generateSSHGuardSummary(finalEvent, common);
            break;
        case 'web_portal':
            sections = generateWebPortalSummary(finalEvent, common);
            break;
        default:
            sections = generateSystemSummary(finalEvent, common);
            break;
    }
    
    return rawMessageSection + sections + generateTagsSection(common.tags);
}

/**
 * Generate firewall traffic summary
 */
function generateFirewallSummary(event, common) {
    const action = event['event']?.['action'] || 'N/A';
    return `
        <div class="summary-grid">
            <div class="summary-section">
                <h3>🌐 Network Traffic</h3>
                <div class="summary-item">
                    <span class="summary-label">Source IP:</span>
                    <span class="summary-value ip">${escapeHtml(event['source']?.['ip'] || 'N/A')}${event['source']?.['domain'] ? ` (${escapeHtml(event['source']['domain'])})` : ''}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Source Port:</span>
                    <span class="summary-value port">${escapeHtml(String(event['source']?.['port'] || 'N/A'))}${event['source']?.['service']?.['name'] ? ` (${escapeHtml(event['source']['service']['name'])})` : ''}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Destination IP:</span>
                    <span class="summary-value ip">${escapeHtml(event['destination']?.['ip'] || 'N/A')}${event['destination']?.['domain'] ? ` (${escapeHtml(event['destination']['domain'])})` : ''}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Destination Port:</span>
                    <span class="summary-value port">${escapeHtml(String(event['destination']?.['port'] || 'N/A'))}${event['destination']?.['service']?.['name'] ? ` (${escapeHtml(event['destination']['service']['name'])})` : ''}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Protocol:</span>
                    <span class="summary-value">${escapeHtml(String(event['network']?.['protocol'] || 'N/A')).toUpperCase()}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Network Type:</span>
                    <span class="summary-value">${escapeHtml(String(event['network']?.['type'] || 'N/A')).toUpperCase()}</span>
                </div>
            </div>
            
            <div class="summary-section">
                <h3>🔥 Firewall Details</h3>
                <div class="summary-item">
                    <span class="summary-label">Action:</span>
                    <span class="summary-value action ${action.toLowerCase()}">${escapeHtml(String(action)).toUpperCase()}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Direction:</span>
                    <span class="summary-value">${escapeHtml(String(event['network']?.['direction'] || 'N/A')).toUpperCase()}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Interface:</span>
                    <span class="summary-value">${escapeHtml(event['interface']?.['name'] || 'N/A')}${event['interface']?.['alias'] ? ` (${escapeHtml(event['interface']['alias'])})` : ''}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Rule ID:</span>
                    <span class="summary-value">${escapeHtml(String(event['rule']?.['id'] || 'N/A'))}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Rule UUID:</span>
                    <span class="summary-value">${escapeHtml(String(event['rule']?.['uuid'] || 'N/A'))}</span>
                </div>
                ${event['rule']?.['description'] ? `
                <div class="summary-item">
                    <span class="summary-label">Rule Description:</span>
                    <span class="summary-value">${escapeHtml(event['rule']['description'])}</span>
                </div>
                ` : ''}
                <div class="summary-item">
                    <span class="summary-label">Hostname:</span>
                    <span class="summary-value">${escapeHtml(common.hostname)}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Timestamp:</span>
                    <span class="summary-value">${escapeHtml(common.timestamp)}</span>
                </div>
            </div>
        </div>
    `;
}

/**
 * Generate Suricata IDS summary
 */
function generateSuricataSummary(event, common) {
    const alert = event['suricata']?.['eve']?.['alert'] || {};
    const signature = alert['signature'] || 'N/A';
    const severity = alert['severity'] || 'N/A';
    const category = alert['category'] || 'N/A';
    
    return `
        <div class="summary-grid">
            <div class="summary-section">
                <h3>🚨 IDS Alert</h3>
                <div class="summary-item">
                    <span class="summary-label">Signature:</span>
                    <span class="summary-value">${escapeHtml(signature)}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Severity:</span>
                    <span class="summary-value">${escapeHtml(String(severity))}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Category:</span>
                    <span class="summary-value">${escapeHtml(category)}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Event Type:</span>
                    <span class="summary-value">${escapeHtml(event['suricata']?.['eve']?.['event_type'] || 'N/A')}</span>
                </div>
            </div>
            
            <div class="summary-section">
                <h3>🌐 Network Information</h3>
                <div class="summary-item">
                    <span class="summary-label">Source IP:</span>
                    <span class="summary-value ip">${escapeHtml(event['source']?.['ip'] || 'N/A')}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Destination IP:</span>
                    <span class="summary-value ip">${escapeHtml(event['destination']?.['ip'] || 'N/A')}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Protocol:</span>
                    <span class="summary-value">${escapeHtml(String(event['network']?.['protocol'] || 'N/A')).toUpperCase()}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Timestamp:</span>
                    <span class="summary-value">${escapeHtml(common.timestamp)}</span>
                </div>
            </div>
        </div>
    `;
}

/**
 * Generate DNS summary
 */
function generateDNSSummary(event, common) {
    const dns = event['dns'] || {};
    const dnssec = event['dnssec'] || {};
    const process = event['process'] || {};
    const logLevel = event['log']?.['level'] || 'N/A';
    
    // Determine if this is a DNSSEC message
    const isDNSSEC = dnssec['message_type'] !== undefined;
    const tags = event['tags'] || [];
    const isDNSSECValidation = tags.includes('dnssec_validation');
    const isDNSSECProof = tags.includes('dnssec_proof');
    const isDNSSECFailure = tags.includes('dnssec_failure');
    const isNetworkError = tags.includes('network_error');
    
    // Check if this is a response status message
    const isResponseStatus = dns['message_type'] === 'response_status';
    
    let sections = '';
    
    // DNS Response Status Section (for response status messages)
    if (isResponseStatus) {
        sections += `
            <div class="summary-section">
                <h3>📊 DNS Response Status</h3>
                <div class="summary-item">
                    <span class="summary-label">Response Status:</span>
                    <span class="summary-value action ${dns['response_status']?.toLowerCase()}">${escapeHtml(String(dns['response_status'] || 'N/A').toUpperCase())}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Response Type:</span>
                    <span class="summary-value">${escapeHtml(String(dns['response_type'] || 'N/A').toUpperCase())}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Message Type:</span>
                    <span class="summary-value">${escapeHtml(dns['message_type'])}</span>
                </div>
            </div>
        `;
    }
    // DNS Query Section (if present)
    else if (dns['question']) {
        sections += `
            <div class="summary-section">
                <h3>🔍 DNS Query</h3>
                <div class="summary-item">
                    <span class="summary-label">Query Name:</span>
                    <span class="summary-value">${escapeHtml(dns['question']['name'] || 'N/A')}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Query Type:</span>
                    <span class="summary-value">${escapeHtml(String(dns['question']['type'] || 'N/A')).toUpperCase()}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Query Class:</span>
                    <span class="summary-value">${escapeHtml(String(dns['question']['class'] || 'N/A')).toUpperCase()}</span>
                </div>
                ${dns['response_code'] ? `
                <div class="summary-item">
                    <span class="summary-label">Response Code:</span>
                    <span class="summary-value">${escapeHtml(String(dns['response_code']).toUpperCase())}</span>
                </div>
                ` : ''}
                ${dns['action'] ? `
                <div class="summary-item">
                    <span class="summary-label">Action:</span>
                    <span class="summary-value">${escapeHtml(String(dns['action']))}</span>
                </div>
                ` : ''}
            </div>
        `;
    }
    
    // DNSSEC Section (if present)
    if (isDNSSEC) {
        let dnssecIcon = '🔐';
        let dnssecTitle = 'DNSSEC Information';
        
        if (isDNSSECValidation) {
            dnssecIcon = '✅';
            dnssecTitle = 'DNSSEC Validation';
        } else if (isDNSSECProof) {
            dnssecIcon = '📜';
            dnssecTitle = 'DNSSEC Proof';
        } else if (isDNSSECFailure) {
            dnssecIcon = '❌';
            dnssecTitle = 'DNSSEC Failure';
        }
        
        sections += `
            <div class="summary-section">
                <h3>${dnssecIcon} ${dnssecTitle}</h3>
                <div class="summary-item">
                    <span class="summary-label">Message Type:</span>
                    <span class="summary-value">${escapeHtml(dnssec['message_type'] || 'N/A')}</span>
                </div>
                ${dnssec['validation_state'] ? `
                <div class="summary-item">
                    <span class="summary-label">Validation State:</span>
                    <span class="summary-value action ${dnssec['validation_state'].toLowerCase()}">${escapeHtml(String(dnssec['validation_state']).toUpperCase())}</span>
                </div>
                ` : ''}
                ${dnssec['response_type'] ? `
                <div class="summary-item">
                    <span class="summary-label">Response Type:</span>
                    <span class="summary-value">${escapeHtml(dnssec['response_type'])}</span>
                </div>
                ` : ''}
                ${dnssec['proof_type'] ? `
                <div class="summary-item">
                    <span class="summary-label">Proof Type:</span>
                    <span class="summary-value">${escapeHtml(dnssec['proof_type'])}</span>
                </div>
                ` : ''}
                ${dnssec['target'] ? `
                <div class="summary-item">
                    <span class="summary-label">Target:</span>
                    <span class="summary-value">${escapeHtml(dnssec['target'])}</span>
                </div>
                ` : ''}
                ${dnssec['result'] ? `
                <div class="summary-item">
                    <span class="summary-label">Result:</span>
                    <span class="summary-value">${escapeHtml(dnssec['result'])}</span>
                </div>
                ` : ''}
                ${dnssec['action'] ? `
                <div class="summary-item">
                    <span class="summary-label">Action:</span>
                    <span class="summary-value">${escapeHtml(dnssec['action'])}</span>
                </div>
                ` : ''}
                ${dnssec['details'] ? `
                <div class="summary-item">
                    <span class="summary-label">Details:</span>
                    <span class="summary-value">${escapeHtml(dnssec['details'])}</span>
                </div>
                ` : ''}
            </div>
        `;
    }
    
    // Network Error Section (if present)
    if (isNetworkError && event['network']?.['error']) {
        sections += `
            <div class="summary-section">
                <h3>⚠️ Network Error</h3>
                <div class="summary-item">
                    <span class="summary-label">Error:</span>
                    <span class="summary-value">${escapeHtml(event['network']['error'])}</span>
                </div>
            </div>
        `;
    }
    
    // Process & System Details Section
    sections += `
        <div class="summary-section">
            <h3>💻 System Details</h3>
            ${process['pgid'] ? `
            <div class="summary-item">
                <span class="summary-label">Process ID:</span>
                <span class="summary-value">${escapeHtml(String(process['pgid']))}${process['thread']?.['id'] ? `:${escapeHtml(String(process['thread']['id']))}` : ''}</span>
            </div>
            ` : ''}
            <div class="summary-item">
                <span class="summary-label">Log Level:</span>
                <span class="summary-value">${escapeHtml(String(logLevel).toUpperCase())}</span>
            </div>
            ${event['source']?.['ip'] || event['client']?.['ip'] ? `
            <div class="summary-item">
                <span class="summary-label">Client IP:</span>
                <span class="summary-value ip">${escapeHtml(event['source']?.['ip'] || event['client']?.['ip'])}</span>
            </div>
            ` : ''}
            <div class="summary-item">
                <span class="summary-label">Hostname:</span>
                <span class="summary-value">${escapeHtml(common.hostname)}</span>
            </div>
            <div class="summary-item">
                <span class="summary-label">Timestamp:</span>
                <span class="summary-value">${escapeHtml(common.timestamp)}</span>
            </div>
        </div>
    `;
    
    return `<div class="summary-grid">${sections}</div>`;
}


/**
 * Generate DHCP summary
 */
function generateDHCPSummary(event, common) {
    const dhcp = event['dhcp'] || {};
    const dhcpv4 = event['dhcpv4'] || {};
    const dhcpv6 = event['dhcpv6'] || {};
    
    // Get operation type
    const operation = dhcp['operation'] || event['event']?.['action'] || 'UNKNOWN';
    
    // Determine icon and styling based on operation type
    let icon = '📡';
    let operationClass = 'info';
    
    switch(operation.toUpperCase()) {
        case 'DISCOVER':
            icon = '🔍';
            operationClass = 'info';
            break;
        case 'OFFER':
            icon = '💬';
            operationClass = 'warning';
            break;
        case 'REQUEST':
            icon = '📤';
            operationClass = 'info';
            break;
        case 'ACK':
        case 'ACKNOWLEDGEMENT':
            icon = '✅';
            operationClass = 'success';
            break;
        case 'NACK':
        case 'NAK':
            icon = '❌';
            operationClass = 'failure';
            break;
        case 'RELEASE':
            icon = '🔴';
            operationClass = 'warning';
            break;
        case 'DECLINE':
            icon = '⛔';
            operationClass = 'failure';
            break;
        case 'INFORM':
            icon = 'ℹ️';
            operationClass = 'info';
            break;
    }
    
    // Collect Client Info - try both IPv4 and IPv6
    const clientMac = dhcpv4['client']?.['mac'] || dhcpv6['client']?.['mac'] || 'N/A';
    const clientIp = dhcpv4['client']?.['ip'] || dhcpv6['client']?.['ip'] || 'N/A';
    const hostname = dhcpv4['option']?.['hostname'] || dhcpv6['option']?.['hostname'] || 'N/A';
    
    return `
        <div class="summary-grid">
            <div class="summary-section">
                <h3>${icon} DHCP ${operation.toUpperCase()}</h3>
                <div class="summary-item">
                    <span class="summary-label">Status:</span>
                    <span class="summary-value action ${operationClass}">${operation.toUpperCase()}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Client IP:</span>
                    <span class="summary-value ip">${escapeHtml(clientIp)}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Client MAC:</span>
                    <span class="summary-value">${escapeHtml(clientMac)}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Hostname:</span>
                    <span class="summary-value">${escapeHtml(hostname)}</span>
                </div>
            </div>
            
            <div class="summary-section">
                <h3>📋 Details</h3>
                <div class="summary-item">
                    <span class="summary-label">Server:</span>
                    <span class="summary-value">${escapeHtml(common.hostname)}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Timestamp:</span>
                    <span class="summary-value">${escapeHtml(common.timestamp)}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Dataset:</span>
                    <span class="summary-value">${escapeHtml(event['event']?.['dataset'] || 'pfelk.dhcp')}</span>
                </div>
            </div>
        </div>
    `;
}

/**
 * Generate OpenVPN summary
 */
function generateOpenVPNSummary(event, common) {
    return `
        <div class="summary-grid">
            <div class="summary-section">
                <h3>🔐 VPN Event</h3>
                <div class="summary-item">
                    <span class="summary-label">Event:</span>
                    <span class="summary-value">${escapeHtml(event['event']?.['action'] || 'N/A')}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">User:</span>
                    <span class="summary-value">${escapeHtml(event['user']?.['name'] || event['openvpn']?.['user'] || 'N/A')}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Client IP:</span>
                    <span class="summary-value ip">${escapeHtml(event['source']?.['ip'] || event['client']?.['ip'] || 'N/A')}</span>
                </div>
            </div>
            
            <div class="summary-section">
                <h3>📋 Details</h3>
                <div class="summary-item">
                    <span class="summary-label">Server:</span>
                    <span class="summary-value">${escapeHtml(common.hostname)}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Timestamp:</span>
                    <span class="summary-value">${escapeHtml(common.timestamp)}</span>
                </div>
            </div>
        </div>
    `;
}

/**
 * Generate SSHGuard attack detection summary
 */
function generateSSHGuardSummary(event, common) {
    const sshguard = event['sshguard'] || {};
    const source = event['source'] || {};
    const eventAction = event['event']?.action || 'unknown';
    
    // Handle blocking events
    if (eventAction === 'blocking') {
        const blockedTarget = sshguard['blocked_target'] || 'N/A';
        const blockDuration = sshguard['block_duration'] || 0;
        const attackCount = sshguard['attack_count'] || 0;
        const attackTimeframe = sshguard['attack_timeframe'] || 0;
        const abuseCount = sshguard['abuse_count'] || 0;
        const abuseTimeframe = sshguard['abuse_timeframe'] || 0;
        
        return `
            <div class="summary-grid">
                <div class="summary-section">
                    <h3>🚫 Host Blocked</h3>
                    <div class="summary-item">
                        <span class="summary-label">Blocked Target:</span>
                        <span class="summary-value ip">${escapeHtml(blockedTarget)}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Block Duration:</span>
                        <span class="summary-value action critical">${blockDuration} seconds</span>
                    </div>
                </div>
                
                <div class="summary-section">
                    <h3>📊 Attack Statistics</h3>
                    <div class="summary-item">
                        <span class="summary-label">Attacks Detected:</span>
                        <span class="summary-value">${attackCount} in ${attackTimeframe}s</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Previous Abuses:</span>
                        <span class="summary-value">${abuseCount} in ${abuseTimeframe}s</span>
                    </div>
                </div>
                
                <div class="summary-section">
                    <h3>📋 Details</h3>
                    <div class="summary-item">
                        <span class="summary-label">Server:</span>
                        <span class="summary-value">${escapeHtml(common.hostname)}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Timestamp:</span>
                        <span class="summary-value">${escapeHtml(common.timestamp)}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Category:</span>
                        <span class="summary-value action threat">Intrusion Detection</span>
                    </div>
                </div>
            </div>
        `;
    }
    
    // Handle attack detection events
    const danger = sshguard['danger'] || 0;
    
    // Determine danger level color/label
    let dangerLabel = 'Low';
    let dangerClass = 'low';
    if (danger >= 50) {
        dangerLabel = 'Critical';
        dangerClass = 'critical';
    } else if (danger >= 30) {
        dangerLabel = 'High';
        dangerClass = 'high';
    } else if (danger >= 10) {
        dangerLabel = 'Medium';
        dangerClass = 'medium';
    }
    
    return `
        <div class="summary-grid">
            <div class="summary-section">
                <h3>⚠️ Attack Detection</h3>
                <div class="summary-item">
                    <span class="summary-label">Attacker IP:</span>
                    <span class="summary-value ip">${escapeHtml(source['ip'] || 'N/A')}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Service:</span>
                    <span class="summary-value">${escapeHtml(sshguard['service'] || 'N/A')}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Danger Score:</span>
                    <span class="summary-value action ${dangerClass}">${danger} (${dangerLabel})</span>
                </div>
            </div>
            
            <div class="summary-section">
                <h3>📋 Details</h3>
                <div class="summary-item">
                    <span class="summary-label">Server:</span>
                    <span class="summary-value">${escapeHtml(common.hostname)}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Timestamp:</span>
                    <span class="summary-value">${escapeHtml(common.timestamp)}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Category:</span>
                    <span class="summary-value action threat">Intrusion Detection</span>
                </div>
            </div>
        </div>
    `;
}

/**
 * Generate web portal authentication summary
 */
function generateWebPortalSummary(event, common) {
    const user = event['user'] || {};
    const source = event['source'] || {};
    const url = event['url'] || {};
    const eventData = event['event'] || {};
    const pf = event['pf'] || {};
    
    // Get username for prominent display
    const username = user['name'] || pf['app']?.['user'] || 'Unknown User';
    
    // Determine auth outcome
    const isAuthFailure = eventData['outcome'] === 'failure' || event['tags']?.includes('authentication_failure');
    const isAuthSuccess = eventData['outcome'] === 'success' || event['tags']?.includes('authentication_success');
    
    let authIcon = '🌐';
    let authStatus = 'Web Portal Activity';
    let authClass = 'info';
    
    if (isAuthFailure) {
        authIcon = '❌';
        authStatus = 'Authentication Failed';
        authClass = 'critical';
    } else if (isAuthSuccess) {
        authIcon = '✅';
        authStatus = 'Authentication Successful';
        authClass = 'success';
    }
    
    return `
        <div class="summary-grid">
            <div class="summary-section">
                <h3>${authIcon} ${authStatus} - User: <span class="action ${authClass}">${escapeHtml(username)}</span></h3>
                <div class="summary-item">
                    <span class="summary-label">Client IP:</span>
                    <span class="summary-value ip">${escapeHtml(source['ip'] || pf['remote']?.['ip'] || 'N/A')}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Page:</span>
                    <span class="summary-value">${escapeHtml(url['path'] || pf['app']?.['page'] || 'N/A')}</span>
                </div>
                ${eventData['action'] ? `
                <div class="summary-item">
                    <span class="summary-label">Action:</span>
                    <span class="summary-value action ${authClass}">${escapeHtml(eventData['action'])}</span>
                </div>
                ` : ''}
            </div>
            
            <div class="summary-section">
                <h3>📋 Details</h3>
                <div class="summary-item">
                    <span class="summary-label">Server:</span>
                    <span class="summary-value">${escapeHtml(common.hostname)}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Timestamp:</span>
                    <span class="summary-value">${escapeHtml(common.timestamp)}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Category:</span>
                    <span class="summary-value">${escapeHtml(eventData['category'] || 'Web Application')}</span>
                </div>
                ${eventData['severity'] !== undefined ? `
                <div class="summary-item">
                    <span class="summary-label">Severity:</span>
                    <span class="summary-value">${eventData['severity']}</span>
                </div>
                ` : ''}
            </div>
        </div>
    `;
}

/**
 * Generate system/generic log summary
 */
function generateSystemSummary(event, common) {
    return `
        <div class="summary-grid">
            <div class="summary-section">
                <h3>📋 System Log</h3>
                <div class="summary-item">
                    <span class="summary-label">Log Type:</span>
                    <span class="summary-value">${escapeHtml(common.logType)}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Hostname:</span>
                    <span class="summary-value">${escapeHtml(common.hostname)}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Timestamp:</span>
                    <span class="summary-value">${escapeHtml(common.timestamp)}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Message:</span>
                    <span class="summary-value">${escapeHtml(String(event['message'] || 'N/A').substring(0, 100))}${event['message']?.length > 100 ? '...' : ''}</span>
                </div>
            </div>
        </div>
    `;
}

/**
 * Generate tags section
 */
function generateTagsSection(tags) {
    if (!tags || tags.length === 0) return '';
    
    return `
        <div class="summary-section" style="margin-top: 20px;">
            <h3>🏷️ Tags</h3>
            <div class="summary-tags">
                ${tags.map(tag => `<span class="summary-tag">${escapeHtml(tag)}</span>`).join('')}
            </div>
        </div>
        <div class="summary-button-row">
            <button class="btn-secondary" onclick="closeSummaryModal()">Close</button>
        </div>
    `;
}

/**
 * Close summary modal
 */
function closeSummaryModal() {
    document.getElementById('summary-modal').style.display = 'none';
}

/**
 * Auto-detect log type based on content
 */
function autoDetectLogType(logContent) {
    if (!logContent) return null;
    
    // Check for different log patterns
    const detections = [
        {
            name: 'pfSense Firewall (syslog)',
            type: 'syslog',
            tags: ['pfelk', 'firewall_raw'],
            pattern: /filterlog/i,
            appname: 'filterlog'
        },
        {
            name: 'pfSense DHCP',
            type: 'syslog',
            tags: ['pfelk', 'dhcp'],
            pattern: /dhcpd/i,
            appname: 'dhcpd'
        },
        {
            name: 'Unbound DNS',
            type: 'unbound',
            tags: ['pfelk', 'unbound_raw'],
            pattern: /unbound/i,
            appname: 'unbound'
        },
        {
            name: 'Suricata IDS',
            type: 'suricata',
            tags: ['pfelk', 'suricata_json_stream'],
            pattern: /suricata|^\s*\{.*"event_type"/i,
            appname: 'suricata'
        },
        {
            name: 'HAProxy',
            type: 'syslog',
            tags: ['pfelk', 'haproxy'],
            pattern: /haproxy/i,
            appname: 'haproxy'
        },
        {
            name: 'NGINX',
            type: 'syslog',
            tags: ['pfelk', 'nginx'],
            pattern: /nginx/i,
            appname: 'nginx'
        },
        {
            name: 'OpenVPN',
            type: 'syslog',
            tags: ['pfelk', 'openvpn'],
            pattern: /openvpn/i,
            appname: 'openvpn'
        },
        {
            name: 'Squid Proxy',
            type: 'syslog',
            tags: ['pfelk', 'squid'],
            pattern: /squid/i,
            appname: 'squid'
        },
        {
            name: 'Generic Syslog',
            type: 'syslog',
            tags: null,
            pattern: /^<\d+>/,
            appname: null
        }
    ];
    
    for (const detection of detections) {
        if (detection.pattern.test(logContent)) {
            return detection;
        }
    }
    
    return {
        name: 'Unknown (auto-parse)',
        type: 'syslog',
        tags: null,
        appname: null
    };
}

/**
 * Update auto-detected type display
 */
function updateAutoDetectedType(logContent) {
    const autoDetectedDiv = document.getElementById('auto-detected-type');
    const detectedTypeName = document.getElementById('detected-type-name');
    
    if (!logContent.trim()) {
        autoDetectedDiv.style.display = 'none';
        return null;
    }
    
    const detected = autoDetectLogType(logContent);
    detectedTypeName.textContent = detected.name;
    autoDetectedDiv.style.display = 'block';
    
    return detected;
}

// Add event listener to log entry textarea for auto-detection
document.getElementById('log-entry').addEventListener('input', function(e) {
    updateAutoDetectedType(e.target.value);
});
