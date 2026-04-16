// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
  console.log('Suraksha Kavach popup loaded - real-time mode');
  
  // Get DOM elements
  const statusElement = document.getElementById('status');
  const detailsElement = document.getElementById('details');
  
  // Check if elements exist
  if (!statusElement || !detailsElement) {
    console.error('Required DOM elements not found');
    return;
  }
  
  // State management
  let currentTabId = null;
  let currentUrl = null;
  let updateTimer = null;
  let lastUpdateTime = 0;
  
  // Function to get risk label based on score
  function getRiskLabel(score) {
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
  
  // Function to get risk color based on score
  function getRiskColor(score) {
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
    detailsElement.innerHTML = '<small>Analyzing current page...</small>';
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
  
  // Function to display scan results with instant updates
  function displayScanResults(scan, tabUrl) {
    const riskLabel = getRiskLabel(scan.score);
    const riskColor = getRiskColor(scan.score);
    
    // Instant URL display
    statusElement.textContent = `Risk Score: ${scan.score} (${riskLabel})`;
    statusElement.style.color = riskColor;
    
    // Build details HTML
    let detailsHTML = '<strong>URL:</strong><br>' + 
                     (tabUrl || scan.url || 'Unknown') + 
                     '<br><br><strong>Reasons:</strong><br>';
    
    if (scan.reasons && scan.reasons.length > 0) {
      detailsHTML += scan.reasons.join('<br>');
    } else {
      detailsHTML += 'No issues found';
    }
    
    // Add timestamp
    if (scan.timestamp) {
      const scanTime = new Date(scan.timestamp).toLocaleTimeString();
      detailsHTML += '<br><br><small>Last scanned: ' + scanTime + '</small>';
    }
    
    // Add risk assessment
    detailsHTML += '<br><br><div style="padding: 8px; border-radius: 4px; background: ' + 
                 riskColor + '20; border-left: 3px solid ' + riskColor + '; margin-top: 8px;">';
    detailsHTML += '<strong style="color: ' + riskColor + ';">Risk Assessment:</strong><br>';
    detailsHTML += '<span style="color: ' + riskColor + ';">This website is classified as <strong>' + riskLabel + '</strong>';
    
    if (scan.score >= 40) {
      detailsHTML += '<br>⚠️ Exercise extreme caution';
    } else if (scan.score >= 20) {
      detailsHTML += '<br>⚠️ Be careful with sensitive information';
    } else if (scan.score > 0) {
      detailsHTML += '<br>✅ Generally safe but stay vigilant';
    } else {
      detailsHTML += '<br>✅ Appears to be safe';
    }
    
    detailsHTML += '</span></div>';
    
    detailsElement.innerHTML = detailsHTML;
    
    console.log('Instant display updated for:', tabUrl, 'Risk:', riskLabel);
  }
  
  // Function to load and display scan results with optimization
  async function loadScanResults() {
    try {
      // Debounce rapid calls
      const now = Date.now();
      if (now - lastUpdateTime < 100) { // 100ms debounce
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
      
      // Get scan data from storage (optimized)
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
          detailsElement.textContent = 'Please refresh the page for a new scan.';
          statusElement.style.color = '#f57c00';
          return;
        }
        
        // Display results instantly
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
      updateTimer = setTimeout(loadScanResults, 50); // 50ms delay
    });
    
    // Listen for tab updates
    chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
      if (changeInfo.status === 'complete' && tab.url) {
        console.log('Tab updated:', tab.url);
        clearTimeout(updateTimer);
        updateTimer = setTimeout(loadScanResults, 50); // 50ms delay
      }
    });
  }
  
  // Initial load
  loadScanResults();
  
  // Setup real-time monitoring
  setupTabMonitoring();
  
  // Set up faster periodic refresh
  setInterval(loadScanResults, 1000); // Reduced from 2000ms to 1000ms
  
  // Listen for storage changes for instant updates
  chrome.storage.onChanged.addListener(function(changes, namespace) {
    if (namespace === 'local' && changes.lastScan) {
      console.log('Storage changed, updating popup instantly');
      clearTimeout(updateTimer);
      updateTimer = setTimeout(loadScanResults, 10); // 10ms delay for instant update
    }
  });
  
  console.log('Suraksha Kavach popup initialized with real-time updates');
});
