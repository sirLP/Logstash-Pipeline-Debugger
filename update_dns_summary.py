#!/usr/bin/env python3
"""Update the DNS summary function to include DNSSEC information"""

# Read the file
with open('static/app.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Find the function start and end
start_marker = 'function generateDNSSummary(event, common) {'
end_marker = '\n/**\n * Generate DHCP summary\n */'

start_idx = content.find(start_marker)
end_idx = content.find(end_marker)

if start_idx == -1 or end_idx == -1:
    print("Could not find function markers!")
    exit(1)

# New function
new_function = '''function generateDNSSummary(event, common) {
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
    
    let sections = '';
    
    // DNS Query Section (if present)
    if (dns['question']) {
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

'''

# Replace the function
new_content = content[:start_idx] + new_function + content[end_idx:]

# Write back
with open('static/app.js', 'w', encoding='utf-8') as f:
    f.write(new_content)

print("✅ Successfully updated generateDNSSummary function!")
