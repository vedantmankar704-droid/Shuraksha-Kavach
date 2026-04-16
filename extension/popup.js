// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
  console.log('Suraksha Kavach popup loaded - critical phishing detection');
  
  // Get DOM elements
  const statusElement = document.getElementById('status');
  const detailsElement = document.getElementById('details');
  
  // Check if elements exist
  if (!statusElement || !detailsElement) {
    console.error('Required DOM elements not found');
    return;
  }
  
  // STRICT exact-match trusted domains whitelist only
  const TRUSTED_DOMAINS = [
    'github.com',
    'google.com',
    'openai.com',
    'chatgpt.com'
  ];
  
  // Function to check if domain is EXACTLY trusted (no subdomains)
  function isExactTrustedDomain(hostname) {
    return TRUSTED_DOMAINS.includes(hostname);
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
  
  // Function to get risk label based on score and trust level
  function getRiskLabel(score, trustLevel, urlAnalysis) {
    // Priority 1: Exact trusted domains
    if (trustLevel === 'trusted') {
      return 'Trusted Website';
    }
    
    // Priority 2: High risk phishing indicators
    if (urlAnalysis && urlAnalysis.suspiciousKeywordCount >= 3) {
      return 'High Risk';
    }
    
    // Priority 3: Normal risk scoring
    if (score === 0) {
      return 'Safe';
    } else if (score >= 1 && score <= 19) {
      return 'Low Risk';
    } else if (score >= 20 && score <= 39) {
      return 'Medium Risk';
    } else if (score >= 40) {
      return 'High Risk';
    }
    return 'Unknown';
  }
  
  // Function to get risk color based on score and trust level
  function getRiskColor(score, trustLevel, urlAnalysis) {
    // Trusted domains always get green color
    if (trustLevel === 'trusted') {
      return '#388e3c'; // Green
    }
    
    // High risk phishing indicators get red
    if (urlAnalysis && urlAnalysis.suspiciousKeywordCount >= 3) {
      return '#d32f2f'; // Red
    }
    
    // Normal color logic
    if (score === 0) {
      return '#388e3c'; // Green
    } else if (score >= 1 && score <= 19) {
      return '#fbc02d'; // Yellow
    } else if (score >= 20 && score <= 39) {
      return '#f57c00'; // Orange
    } else if (score >= 40) {
      return '#d32f2f'; // Red
    }
    return '#666666'; // Gray
  }
  
  // Function to show loading state instantly
  function showLoadingState() {
    statusElement.textContent = 'Scanning...';
    statusElement.style.color = '#666666';
    detailsElement.innerHTML = '<small>Analyzing URL structure for phishing indicators...</small>';
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
  
  // Function to display scan results with enhanced phishing detection
  function displayScanResults(scan, tabUrl) {
    // Extract hostname to check trust level
    const hostname = extractHostname(tabUrl || scan.url || '');
    const trustLevel = isExactTrustedDomain(hostname) ? 'trusted' : 'unknown';
    
    const urlAnalysis = scan.urlAnalysis || {};
    const riskLabel = getRiskLabel(scan.score, trustLevel, urlAnalysis);
    const riskColor = getRiskColor(scan.score, trustLevel, urlAnalysis);
    
    // Enhanced status display for phishing detection
    if (trustLevel === 'trusted') {
      statusElement.innerHTML = `<strong>Trusted Website</strong><br><small style="color: ${riskColor}; font-weight: normal;">Risk Score: ${scan.score}</small>`;
    } else if (urlAnalysis.suspiciousKeywordCount >= 3) {
      statusElement.innerHTML = `<strong>PHISHING WARNING</strong><br><small style="color: ${riskColor}; font-weight: normal;">Risk Score: ${scan.score}</small>`;
    } else {
      statusElement.textContent = `Risk Score: ${scan.score} (${riskLabel})`;
    }
    statusElement.style.color = riskColor;
    
    // Build details HTML with enhanced phishing information
    let detailsHTML = '<strong>URL:</strong><br>' + 
                     (tabUrl || scan.url || 'Unknown') + 
                     '<br><br><strong>Security Analysis:</strong><br>';
    
    // Show URL analysis results
    if (urlAnalysis.suspiciousKeywordCount > 0) {
      detailsHTML += `<br><strong style="color: ${riskColor};">PHISHING INDICATORS DETECTED:</strong><br>`;
      detailsHTML += `&bull; Suspicious keywords found: <strong>${urlAnalysis.suspiciousKeywords.join(', ')}</strong><br>`;
      detailsHTML += `&bull; Keyword count: <strong>${urlAnalysis.suspiciousKeywordCount}</strong><br>`;
      
      if (scan.reasons && scan.reasons.length > 0) {
        detailsHTML += '<br><strong>Detailed Reasons:</strong><br>';
        scan.reasons.forEach(reason => {
          detailsHTML += `&bull; ${reason}<br>`;
        });
      }
    } else {
      detailsHTML += '<br>No suspicious keywords detected in URL structure<br>';
    }
    
    // Show structural issues
    if (urlAnalysis.structuralIssues && urlAnalysis.structuralIssues.length > 0) {
      detailsHTML += '<br><strong>Structural Issues:</strong><br>';
      urlAnalysis.structuralIssues.forEach(issue => {
        detailsHTML += `&bull; ${issue}<br>`;
      });
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
    
    if (trustLevel === 'trusted') {
      detailsHTML += '<strong>Verified Trusted Platform</strong><br>';
      detailsHTML += 'This is an officially trusted domain with significantly reduced risk.';
    } else if (urlAnalysis.suspiciousKeywordCount >= 3) {
      detailsHTML += '<strong>PHISHING THREAT DETECTED</strong><br>';
      detailsHTML += 'This URL shows strong indicators of being a phishing attempt.<br>';
      detailsHTML += '<strong>DO NOT enter passwords, OTP, or banking information.</strong>';
    } else if (scan.score >= 40) {
      detailsHTML += '<strong>High Risk Website</strong><br>';
      detailsHTML += 'Multiple suspicious indicators detected. Exercise extreme caution.';
    } else if (scan.score >= 20) {
      detailsHTML += '<strong>Medium Risk Website</strong><br>';
      detailsHTML += 'Some suspicious indicators detected. Be careful with sensitive information.';
    } else if (scan.score > 0) {
      detailsHTML += '<strong>Low Risk Website</strong><br>';
      detailsHTML += 'Minor indicators detected. Generally safe but stay vigilant.';
    } else {
      detailsHTML += '<strong>Safe Website</strong><br>';
      detailsHTML += 'No suspicious indicators detected. Appears to be legitimate.';
    }
    
    detailsHTML += '</span></div>';
    
    // Add trust indicator for exact trusted domains only
    if (trustLevel === 'trusted') {
      detailsHTML += '<br><div style="padding: 8px; border-radius: 4px; background: #e8f5e8; border: 2px solid #4caf50; margin-top: 8px; text-align: center;">';
      detailsHTML += '<span style="color: #2e7d32; font-weight: bold; font-size: 13px;">';
      detailsHTML += 'VERIFIED TRUSTED DOMAIN<br>';
      detailsHTML += 'Exact match with official whitelist';
      detailsHTML += '</span></div>';
    }
    
    // Add phishing warning for high-risk URLs
    if (urlAnalysis.suspiciousKeywordCount >= 3 || scan.score >= 40) {
      detailsHTML += '<br><div style="padding: 8px; border-radius: 4px; background: #ffebee; border: 2px solid #f44336; margin-top: 8px; text-align: center;">';
      detailsHTML += '<span style="color: #c62828; font-weight: bold; font-size: 13px;">';
      detailsHTML += 'PHISHING PROTECTION ACTIVE<br>';
      detailsHTML += 'URL structure analysis detected threats';
      detailsHTML += '</span></div>';
    }
    
    detailsElement.innerHTML = detailsHTML;
    
    console.log('Enhanced phishing detection display updated for:', tabUrl, 'Risk:', riskLabel, 'Trust:', trustLevel, 'Keywords:', urlAnalysis.suspiciousKeywordCount);
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
        
        // Display results with enhanced phishing detection
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
  
  console.log('Suraksha Kavach popup initialized with critical phishing detection');
});
