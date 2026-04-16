// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
  console.log('Suraksha Kavach popup loaded');
  
  // Get DOM elements
  const statusElement = document.getElementById('status');
  const detailsElement = document.getElementById('details');
  
  // Check if elements exist
  if (!statusElement || !detailsElement) {
    console.error('Required DOM elements not found');
    return;
  }
  
  // Function to load and display scan results
  function loadScanResults() {
    try {
      chrome.storage.local.get(['lastScan', 'lastUpdated'], function(data) {
        // Check for Chrome runtime errors
        if (chrome.runtime.lastError) {
          console.error('Chrome runtime error:', chrome.runtime.lastError);
          statusElement.textContent = 'Error loading data';
          detailsElement.textContent = chrome.runtime.lastError.message;
          return;
        }
        
        // Check if scan data exists
        if (!data.lastScan) {
          statusElement.textContent = 'No scan result yet';
          detailsElement.textContent = 'Open any website and refresh once.';
          return;
        }
        
        // Check if data is stale (older than 5 minutes)
        const now = Date.now();
        const dataAge = now - (data.lastUpdated || data.lastScan.timestamp || 0);
        const maxAge = 5 * 60 * 1000; // 5 minutes
        
        if (dataAge > maxAge) {
          statusElement.textContent = 'Data is stale';
          detailsElement.textContent = 'Please refresh the page for a new scan.';
          statusElement.style.color = '#f57c00';
          return;
        }
        
        // Display scan results
        const scan = data.lastScan;
        
        // Set risk score with color coding
        let riskScore = 'Risk Score: ' + scan.score;
        if (scan.score >= 50) {
          riskScore += ' (High Risk)';
          statusElement.style.color = '#d32f2f';
        } else if (scan.score >= 30) {
          riskScore += ' (Medium Risk)';
          statusElement.style.color = '#f57c00';
        } else if (scan.score > 0) {
          riskScore += ' (Low Risk)';
          statusElement.style.color = '#fbc02d';
        } else {
          riskScore += ' (Safe)';
          statusElement.style.color = '#388e3c';
        }
        
        statusElement.textContent = riskScore;
        
        // Display URL and reasons
        let detailsHTML = '<strong>URL:</strong><br>' + 
                         (scan.url || 'Unknown') + 
                         '<br><br><strong>Reasons:</strong><br>';
        
        if (scan.reasons && scan.reasons.length > 0) {
          detailsHTML += scan.reasons.join('<br>');
        } else {
          detailsHTML += 'No issues found';
        }
        
        // Add timestamp if available
        if (scan.timestamp) {
          const scanTime = new Date(scan.timestamp).toLocaleTimeString();
          detailsHTML += '<br><br><small>Last scanned: ' + scanTime + '</small>';
        }
        
        detailsElement.innerHTML = detailsHTML;
        
        console.log('Popup data loaded successfully for:', scan.url);
      });
      
    } catch (error) {
      console.error('Error loading popup data:', error);
      statusElement.textContent = 'Error occurred';
      detailsElement.textContent = 'Please try again later.';
    }
  }
  
  // Load initial data
  loadScanResults();
  
  // Set up periodic refresh to get latest data
  setInterval(loadScanResults, 2000);
  
  // Also try to get current tab's URL and trigger scan if needed
  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    if (tabs.length > 0 && tabs[0].url) {
      const currentTabUrl = tabs[0].url;
      console.log('Current tab URL:', currentTabUrl);
      
      // Check if current tab URL matches stored scan URL
      chrome.storage.local.get(['lastScan'], function(data) {
        if (data.lastScan && data.lastScan.url !== currentTabUrl) {
          console.log('URL mismatch, triggering new scan');
          // Send message to content script to rescan
          chrome.tabs.sendMessage(tabs[0].id, { 
            type: 'FORCE_SCAN' 
          }, function(response) {
            if (chrome.runtime.lastError) {
              console.log('Could not contact content script:', chrome.runtime.lastError.message);
            }
          });
        }
      });
    }
  });
});
