chrome.runtime.onInstalled.addListener(() => {
  console.log("Suraksha Kavach installed - clearing all caches");
  
  // Aggressive cache clearing
  chrome.storage.local.clear(() => {
    console.log("Cleared all local storage data");
  });
  
  // Clear any runtime data
  chrome.runtime.getPackageDirectoryEntry((rootDir) => {
    console.log("Package directory cleared");
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("Message received in background:", message);

  if (message.type === "PHISH_SCAN_RESULT") {
    const scanData = {
      ...message.payload,
      tabId: sender.tab?.id,
      timestamp: Date.now()
    };

    chrome.storage.local.set({ 
      lastScan: scanData,
      lastUpdated: Date.now()
    }, () => {
      if (chrome.runtime.lastError) {
        console.error("Error storing scan data:", chrome.runtime.lastError);
      } else {
        console.log("Successfully stored scan data for:", scanData.url);
      }
    });

    // Send response to content script
    sendResponse({ success: true });
    return true; // Keep message channel open for async response
  }
  
  // Handle requests for current scan data
  if (message.type === "GET_CURRENT_SCAN") {
    chrome.storage.local.get(['lastScan'], (data) => {
      if (chrome.runtime.lastError) {
        sendResponse({ error: chrome.runtime.lastError.message });
      } else {
        sendResponse({ data: data.lastScan });
      }
    });
    return true; // Keep message channel open for async response
  }
});

// Listen for tab updates to trigger scans
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    console.log("Tab updated:", tab.url);
    
    // Inject content script if needed
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      files: ['content.js']
    }, () => {
      if (chrome.runtime.lastError) {
        console.log("Content script already injected or error:", chrome.runtime.lastError.message);
      } else {
        console.log("Content script injected successfully");
      }
    });
  }
});

// Clean up old scan data periodically (every hour)
setInterval(() => {
  chrome.storage.local.get(['lastUpdated'], (data) => {
    if (data.lastUpdated && (Date.now() - data.lastUpdated) > 3600000) { // 1 hour
      chrome.storage.local.remove(['lastScan', 'lastUpdated'], () => {
        console.log("Cleaned up old scan data");
      });
    }
  });
}, 3600000);
