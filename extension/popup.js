// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
  console.log('Suraksha Kavach popup loaded - enhanced hostname risk scoring');
  
  // Get DOM elements
  const statusElement = document.getElementById('status');
  const detailsElement = document.getElementById('details');
  
  // Check if elements exist
  if (!statusElement || !detailsElement) {
    console.error('Required DOM elements not found');
    return;
  }
  
  // STRONG trusted domain whitelist with subdomains
  const TRUSTED_DOMAINS = [
    'github.com',
    'google.com',
    'openai.com',
    'instagram.com',
    'whatsapp.com',
    'linkedin.com',
    'telegram.org',
    'facebook.com',
    'twitter.com',
    'youtube.com',
    'microsoft.com',
    'apple.com',
    'amazon.com',
    'netflix.com'
  ];
  
  // Function to check if domain is trusted (including subdomains)
  function isTrustedDomain(hostname) {
    const hostnameLower = hostname.toLowerCase();
    
    // Check exact match first
    if (TRUSTED_DOMAINS.includes(hostnameLower)) {
      return { trusted: true, type: 'exact' };
    }
    
    // Check subdomain match
    for (const trustedDomain of TRUSTED_DOMAINS) {
      if (hostnameLower === trustedDomain) {
        continue; // Skip exact match (already checked)
      }
      if (hostnameLower.endsWith('.' + trustedDomain)) {
        return { trusted: true, type: 'subdomain', baseDomain: trustedDomain };
      }
    }
    
    return { trusted: false, type: 'unknown' };
  }
  
  // Function to extract hostname from URL
  function extractHostname(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch (error) {
      console.error('Error extracting hostname:', error);
      return '';
    }
  }
  
  // State management
  let currentTabId = null;
  let currentUrl = null;
  let updateTimer = null;
  let lastUpdateTime = 0;
  
  // Function to get risk label based on thresholds and trust level
  function getRiskLabel(score, trustInfo) {
    // Priority 1: Trusted domains (always trusted)
    if (trustInfo.trusted) {
      return 'TRUSTED WEBSITE';
    }
    
    // Priority 2: Risk thresholds
    if (score >= 0 && score <= 4) {
      return 'Safe';
    } else if (score >= 5 && score <= 14) {
      return 'Low Risk';
    } else if (score >= 15 && score <= 24) {
      return 'Medium Risk';
    } else if (score >= 25) {
      return 'High Risk';
    }
    return 'Unknown';
  }
  
  // Function to get risk color based on thresholds and trust level
  function getRiskColor(score, trustInfo) {
    // Trusted domains always get green color
    if (trustInfo.trusted) {
      return '#388e3c'; // Green
    }
    
    // Color logic based on thresholds
    if (score >= 0 && score <= 4) {
      return '#388e3c'; // Green
    } else if (score >= 5 && score <= 14) {
      return '#fbc02d'; // Yellow
    } else if (score >= 15 && score <= 24) {
      return '#f57c00'; // Orange
    } else if (score >= 25) {
      return '#d32f2f'; // Red
    }
    return '#666666'; // Gray
  }
  
  // Function to show loading state instantly
  function showLoadingState() {
    statusElement.textContent = 'Scanning...';
    statusElement.style.color = '#666666';
    detailsElement.innerHTML = '<small>Analyzing hostname with enhanced risk scoring...</small>';
  }
  
  // Function to get active tab info instantly
  function getActiveTabInfo() {
    return new Promise((resolve) => {
      chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
        if (tabs.length > 0) {
          resolve({
            id: tabs[0].id,
            url: tabs[0].url,
            title: tabs[0].title
          });
        } else {
          resolve(null);
        }
      });
    });
  }
  
  // Function to display scan results with enhanced hostname analysis
  function displayScanResults(scan, tabUrl) {
    // Extract hostname to check trust level
    const hostname = extractHostname(tabUrl || scan.url || '');
    const trustInfo = isTrustedDomain(hostname);
    
    const riskLabel = getRiskLabel(scan.score, trustInfo);
    const riskColor = getRiskColor(scan.score, trustInfo);
    
    // Enhanced status display with trust information
    if (trustInfo.trusted) {
      statusElement.innerHTML = `<strong>TRUSTED WEBSITE</strong><br><small style="color: ${riskColor}; font-weight: normal;">Risk Score: ${scan.score}</small>`;
    } else if (scan.score >= 25) {
      statusElement.innerHTML = `<strong>PHISHING WARNING</strong><br><small style="color: ${riskColor}; font-weight: normal;">Risk Score: ${scan.score}</small>`;
    } else if (scan.score >= 15) {
      statusElement.innerHTML = `<strong>SECURITY WARNING</strong><br><small style="color: ${riskColor}; font-weight: normal;">Risk Score: ${scan.score}</small>`;
    } else {
      statusElement.textContent = `Risk Score: ${scan.score} (${riskLabel})`;
    }
    statusElement.style.color = riskColor;
    
    // Build details HTML with enhanced hostname analysis
    let detailsHTML = '<strong>URL:</strong><br>' + 
                     (tabUrl || scan.url || 'Unknown') + 
                     '<br><br><strong>Enhanced Hostname Analysis:</strong><br>';
    
    // Show trust information
    if (trustInfo.trusted) {
      detailsHTML += `&bull; <strong style="color: #388e3c;">TRUSTED DOMAIN</strong><br>`;
      detailsHTML += `&bull; Type: ${trustInfo.type === 'exact' ? 'Exact match' : 'Subdomain of ' + trustInfo.baseDomain}<br>`;
      detailsHTML += `&bull; Risk score significantly reduced (98%)<br>`;
    } else {
      detailsHTML += `&bull; <strong style="color: ${riskColor};">UNTRUSTED DOMAIN</strong><br>`;
      detailsHTML += `&bull; Full hostname analysis applied<br>`;
    }
    
    // Get separated analysis data
    const separatedAnalysis = scan.separatedAnalysis || {};
    const hostnameAnalysis = separatedAnalysis.hostname || {};
    const pathAnalysis = separatedAnalysis.path || {};
    const queryAnalysis = separatedAnalysis.query || {};
    const structuralAnalysis = separatedAnalysis.structural || {};
    
    // Show enhanced hostname analysis details
    if (hostnameAnalysis.details && hostnameAnalysis.details.length > 0) {
      detailsHTML += '<br><strong style="color: ' + riskColor + ';">Hostname Pattern Detection:</strong><br>';
      
      // Categorize hostname findings for better display
      const phishingStylePatterns = hostnameAnalysis.details.filter(detail => 
        detail.includes('Chained security words') ||
        detail.includes('Multiple security words') ||
        detail.includes('Excessive security words') ||
        detail.includes('Dangerous banking') ||
        detail.includes('Dangerous account')
      );
      
      const suspiciousCombinations = hostnameAnalysis.details.filter(detail => 
        detail.includes('Suspicious domain combination')
      );
      
      const structuralIssues = hostnameAnalysis.details.filter(detail => 
        detail.includes('hyphens') ||
        detail.includes('Complex multi-part')
      );
      
      // Display phishing-style patterns first
      if (phishingStylePatterns.length > 0) {
        detailsHTML += '<br><strong style="color: #d32f2f;">PHISHING-STYLE PATTERNS:</strong><br>';
        phishingStylePatterns.forEach(detail => {
          detailsHTML += `&bull; <strong style="color: #d32f2f;">${detail}</strong><br>`;
        });
      }
      
      // Display suspicious combinations
      if (suspiciousCombinations.length > 0) {
        detailsHTML += '<br><strong style="color: #f57c00;">SUSPICIOUS COMBINATIONS:</strong><br>';
        suspiciousCombinations.forEach(detail => {
          detailsHTML += `&bull; <strong style="color: #f57c00;">${detail}</strong><br>`;
        });
      }
      
      // Display structural issues
      if (structuralIssues.length > 0) {
        detailsHTML += '<br><strong style="color: ' + riskColor + ';">STRUCTURAL ISSUES:</strong><br>';
        structuralIssues.forEach(detail => {
          detailsHTML += `&bull; ${detail}<br>`;
        });
      }
      
      // Display any remaining details
      const otherDetails = hostnameAnalysis.details.filter(detail => 
        !phishingStylePatterns.includes(detail) &&
        !suspiciousCombinations.includes(detail) &&
        !structuralIssues.includes(detail)
      );
      
      if (otherDetails.length > 0) {
        detailsHTML += '<br><strong style="color: ' + riskColor + ';">OTHER FINDINGS:</strong><br>';
        otherDetails.forEach(detail => {
          detailsHTML += `&bull; ${detail}<br>`;
        });
      }
      
    } else if (!trustInfo.trusted) {
      detailsHTML += '<br><strong style="color: ' + riskColor + ';">Hostname Pattern Detection:</strong><br>';
      detailsHTML += '&bull; No suspicious hostname patterns detected<br>';
    }
    
    // Show path analysis details
    if (pathAnalysis.details && pathAnalysis.details.length > 0) {
      detailsHTML += '<br><strong style="color: ' + riskColor + ';">Path Analysis:</strong><br>';
      pathAnalysis.details.forEach(detail => {
        detailsHTML += `&bull; ${detail}<br>`;
      });
    } else if (!trustInfo.trusted) {
      detailsHTML += '<br><strong style="color: ' + riskColor + ';">Path Analysis:</strong><br>';
      detailsHTML += '&bull; No suspicious path patterns detected<br>';
    }
    
    // Show query analysis details
    if (queryAnalysis.details && queryAnalysis.details.length > 0) {
      detailsHTML += '<br><strong style="color: ' + riskColor + ';">Query Analysis:</strong><br>';
      queryAnalysis.details.forEach(detail => {
        detailsHTML += `&bull; ${detail}<br>`;
      });
    } else if (!trustInfo.trusted) {
      detailsHTML += '<br><strong style="color: ' + riskColor + ';">Query Analysis:</strong><br>';
      detailsHTML += '&bull; No suspicious query patterns detected<br>';
    }
    
    // Show structural issues
    if (structuralAnalysis && Object.keys(structuralAnalysis).length > 0) {
      detailsHTML += '<br><strong style="color: ' + riskColor + ';">Structural Security Issues:</strong><br>';
      if (structuralAnalysis.suspiciousTld) {
        detailsHTML += '&bull; Suspicious top-level domain<br>';
      }
      if (structuralAnalysis.ipAddress) {
        detailsHTML += '&bull; IP address instead of domain name<br>';
      }
      if (structuralAnalysis.httpOnly) {
        detailsHTML += '&bull; HTTP-only site (no HTTPS encryption)<br>';
      }
      if (structuralAnalysis.atSymbol) {
        detailsHTML += '&bull; @ symbol in URL (possible obfuscation)<br>';
      }
      if (structuralAnalysis.longUrl) {
        detailsHTML += `&bull; Unusually long URL (${structuralAnalysis.urlLength} characters)<br>`;
      }
    } else if (!trustInfo.trusted) {
      detailsHTML += '<br><strong style="color: ' + riskColor + ';">Structural Security Issues:</strong><br>';
      detailsHTML += '&bull; No structural security issues detected<br>';
    }
    
    // Add timestamp
    if (scan.timestamp) {
      const scanTime = new Date(scan.timestamp).toLocaleTimeString();
      detailsHTML += '<br><br><small>Last scanned: ' + scanTime + '</small>';
    }
    
    // Enhanced risk assessment
    detailsHTML += '<br><br><div style="padding: 10px; border-radius: 4px; background: ' + 
                 riskColor + '20; border-left: 3px solid ' + riskColor + '; margin-top: 8px;">';
    detailsHTML += '<strong style="color: ' + riskColor + '; font-size: 14px;">Risk Assessment:</strong><br>';
    detailsHTML += '<span style="color: ' + riskColor + ';">';
    
    if (trustInfo.trusted) {
      detailsHTML += '<strong>VERIFIED TRUSTED PLATFORM</strong><br>';
      detailsHTML += 'This is an officially trusted domain with significantly reduced risk.';
    } else if (scan.score >= 25) {
      detailsHTML += '<strong>PHISHING THREAT DETECTED</strong><br>';
      detailsHTML += 'This URL shows strong indicators of being a phishing attempt.<br>';
      detailsHTML += '<strong>DO NOT enter passwords, OTP, or banking information.</strong>';
    } else if (scan.score >= 15) {
      detailsHTML += '<strong>Medium Risk Website</strong><br>';
      detailsHTML += 'Multiple suspicious indicators detected. Be careful with sensitive information.';
    } else if (scan.score >= 5) {
      detailsHTML += '<strong>Low Risk Website</strong><br>';
      detailsHTML += 'Some minor indicators detected. Generally safe but stay vigilant.';
    } else {
      detailsHTML += '<strong>Safe Website</strong><br>';
      detailsHTML += 'No suspicious indicators detected. Appears to be legitimate.';
    }
    
    detailsHTML += '</span></div>';
    
    // Add trust indicator for trusted domains
    if (trustInfo.trusted) {
      detailsHTML += '<br><div style="padding: 8px; border-radius: 4px; background: #e8f5e8; border: 2px solid #4caf50; margin-top: 8px; text-align: center;">';
      detailsHTML += '<span style="color: #2e7d32; font-weight: bold; font-size: 13px;">';
      detailsHTML += 'VERIFIED TRUSTED DOMAIN<br>';
      if (trustInfo.type === 'exact') {
        detailsHTML += 'Exact match with official whitelist';
      } else {
        detailsHTML += `Subdomain of ${trustInfo.baseDomain}`;
      }
      detailsHTML += '</span></div>';
    }
    
    // Add phishing warning for high-risk URLs
    if (scan.score >= 25 && !trustInfo.trusted) {
      detailsHTML += '<br><div style="padding: 8px; border-radius: 4px; background: #ffebee; border: 2px solid #f44336; margin-top: 8px; text-align: center;">';
      detailsHTML += '<span style="color: #c62828; font-weight: bold; font-size: 13px;">';
      detailsHTML += 'PHISHING PROTECTION ACTIVE<br>';
      detailsHTML += 'Enhanced hostname analysis detected threats';
      detailsHTML += '</span></div>';
    }
    
    // Add medium risk warning
    if (scan.score >= 15 && scan.score < 25 && !trustInfo.trusted) {
      detailsHTML += '<br><div style="padding: 8px; border-radius: 4px; background: #fff3e0; border: 2px solid #ff9800; margin-top: 8px; text-align: center;">';
      detailsHTML += '<span style="color: #ef6c00; font-weight: bold; font-size: 13px;">';
      detailsHTML += 'SUSPICIOUS HOSTNAME DETECTED<br>';
      detailsHTML += 'Hostname pattern analysis found issues';
      detailsHTML += '</span></div>';
    }
    
    detailsElement.innerHTML = detailsHTML;
    
    console.log('Enhanced hostname scoring display updated for:', tabUrl, 'Risk:', riskLabel, 'Trust:', trustInfo, 'Score:', scan.score);
  }
  
  // Function to load and display scan results
  async function loadScanResults() {
    try {
      // Debounce rapid calls
      const now = Date.now();
      if (now - lastUpdateTime < 100) {
        return;
      }
      lastUpdateTime = now;
      
      // Get active tab info instantly
      const tabInfo = await getActiveTabInfo();
      
      if (!tabInfo) {
        statusElement.textContent = 'No active tab';
        detailsElement.textContent = 'Please open a website.';
        return;
      }
      
      // Check if URL changed
      if (tabInfo.url !== currentUrl) {
        console.log('URL changed from', currentUrl, 'to', tabInfo.url);
        currentUrl = tabInfo.url;
        currentTabId = tabInfo.id;
        
        // Show loading state immediately
        showLoadingState();
        
        // Trigger new scan if needed
        chrome.tabs.sendMessage(tabInfo.id, { 
          type: 'FORCE_SCAN' 
        }, function(response) {
          if (chrome.runtime.lastError) {
            console.log('Content script not ready, will use cached data');
          }
        });
      }
      
      // Get scan data from storage
      chrome.storage.local.get(['lastScan', 'lastUpdated'], function(data) {
        if (chrome.runtime.lastError) {
          console.error('Chrome runtime error:', chrome.runtime.lastError);
          statusElement.textContent = 'Error loading data';
          detailsElement.textContent = chrome.runtime.lastError.message;
          return;
        }
        
        if (!data.lastScan) {
          statusElement.textContent = 'No scan result yet';
          detailsElement.textContent = 'Open any website and refresh once.';
          return;
        }
        
        // Check if scan data matches current tab
        const scan = data.lastScan;
        const dataAge = Date.now() - (data.lastUpdated || scan.timestamp || 0);
        const maxAge = 5 * 60 * 1000; // 5 minutes
        
        if (dataAge > maxAge) {
          statusElement.textContent = 'Data is stale';
          detailsElement.textContent = 'Please refresh page for a new scan.';
          statusElement.style.color = '#f57c00';
          return;
        }
        
        // Display results with enhanced hostname analysis
        displayScanResults(scan, tabInfo.url);
      });
      
    } catch (error) {
      console.error('Error loading popup data:', error);
      statusElement.textContent = 'Error occurred';
      detailsElement.textContent = 'Please try again later.';
    }
  }
  
  // Function to setup real-time tab monitoring
  function setupTabMonitoring() {
    // Listen for tab activation events
    chrome.tabs.onActivated.addListener(function(activeInfo) {
      console.log('Tab activated:', activeInfo.tabId);
      clearTimeout(updateTimer);
      updateTimer = setTimeout(loadScanResults, 50);
    });
    
    // Listen for tab updates
    chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
      if (changeInfo.status === 'complete' && tab.url) {
        console.log('Tab updated:', tab.url);
        clearTimeout(updateTimer);
        updateTimer = setTimeout(loadScanResults, 50);
      }
    });
  }
  
  // Initial load
  loadScanResults();
  
  // Setup real-time monitoring
  setupTabMonitoring();
  
  // Set up faster periodic refresh
  setInterval(loadScanResults, 1000);
  
  // Listen for storage changes for instant updates
  chrome.storage.onChanged.addListener(function(changes, namespace) {
    if (namespace === 'local' && changes.lastScan) {
      console.log('Storage changed, updating popup instantly');
      clearTimeout(updateTimer);
      updateTimer = setTimeout(loadScanResults, 10);
    }
  });
  
  console.log('Suraksha Kavach popup initialized with enhanced hostname scoring');
});
