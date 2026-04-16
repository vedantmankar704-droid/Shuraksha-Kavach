// Minimal content script for testing
console.log('Suraksha Kavach: Minimal script loaded');

// Single global variable
var currentUrl = window.location.href;

function scanWebsite() {
  console.log('Scanning:', window.location.href);
  
  const result = {
    url: window.location.href,
    score: 0,
    reasons: [],
    timestamp: Date.now()
  };
  
  chrome.runtime.sendMessage({
    type: "PHISH_SCAN_RESULT",
    payload: result
  });
}

// Initial scan
setTimeout(scanWebsite, 1000);

// Listen for messages
chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
  if (message.type === 'FORCE_SCAN') {
    scanWebsite();
    sendResponse({ success: true });
  }
  return true;
});

console.log('Current URL:', currentUrl);
