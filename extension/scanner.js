// Suraksha Kavach Scanner - Fresh version to avoid caching
(function() {
    'use strict';
    
    console.log('Suraksha Kavach: Scanner initializing...');
    
    // Global state
    let lastScannedUrl = '';
    let scanTimer = null;
    
    // Main scanning function
    function performScan() {
        try {
            const currentUrl = window.location.href;
            const hostname = window.location.hostname;
            const pageText = document.body ? document.body.innerText.toLowerCase() : '';
            
            // Skip if same URL
            if (currentUrl === lastScannedUrl) {
                console.log('Suraksha Kavach: Same URL, skipping scan');
                return;
            }
            
            console.log('Suraksha Kavach: Scanning URL:', currentUrl);
            lastScannedUrl = currentUrl;
            
            // Calculate risk score
            let score = 0;
            const reasons = [];
            
            // URL checks
            if (currentUrl.length > 75) {
                score += 15;
                reasons.push('Long URL detected');
            }
            
            if (!currentUrl.startsWith('https://')) {
                score += 20;
                reasons.push('No HTTPS');
            }
            
            if (hostname.includes('-')) {
                score += 10;
                reasons.push('Hyphenated domain');
            }
            
            // IP address check
            const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
            if (ipPattern.test(hostname)) {
                score += 30;
                reasons.push('IP address instead of domain');
            }
            
            // Suspicious TLDs
            const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click'];
            if (suspiciousTlds.some(tld => hostname.endsWith(tld))) {
                score += 25;
                reasons.push('Suspicious top-level domain');
            }
            
            // Content checks
            const suspiciousWords = [
                'verify', 'update password', 'urgent action', 'claim reward',
                'bank login', 'otp', 'suspended', 'limited time', 'click here', 'confirm account'
            ];
            
            for (const word of suspiciousWords) {
                if (pageText.includes(word)) {
                    score += 10;
                    reasons.push('Suspicious keyword: ' + word);
                }
            }
            
            // Form checks
            const passwordField = document.querySelector('input[type="password"]');
            if (passwordField) {
                score += 15;
                reasons.push('Password field found');
            }
            
            const forms = document.querySelectorAll('form');
            if (forms.length > 0 && !currentUrl.startsWith('https://')) {
                score += 20;
                reasons.push('Forms on non-HTTPS page');
            }
            
            // Create result
            const result = {
                url: currentUrl,
                hostname: hostname,
                score: score,
                reasons: reasons,
                timestamp: Date.now()
            };
            
            console.log('Suraksha Kavach: Scan result:', result);
            
            // Send to background
            chrome.runtime.sendMessage({
                type: 'PHISH_SCAN_RESULT',
                payload: result
            }, function(response) {
                if (chrome.runtime.lastError) {
                    console.error('Suraksha Kavach: Message error:', chrome.runtime.lastError);
                } else {
                    console.log('Suraksha Kavach: Message sent successfully');
                }
            });
            
        } catch (error) {
            console.error('Suraksha Kavach: Scan error:', error);
        }
    }
    
    // URL change detection
    function checkUrlChange() {
        if (window.location.href !== lastScannedUrl) {
            console.log('Suraksha Kavach: URL change detected');
            clearTimeout(scanTimer);
            scanTimer = setTimeout(performScan, 1000);
        }
    }
    
    // Initialize
    console.log('Suraksha Kavach: Setting up scanner for:', window.location.href);
    
    // Initial scan
    setTimeout(performScan, 1000);
    
    // Periodic checks
    setInterval(checkUrlChange, 2000);
    
    // Navigation events
    window.addEventListener('popstate', checkUrlChange);
    
    // SPA navigation
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;
    
    history.pushState = function() {
        originalPushState.apply(this, arguments);
        setTimeout(checkUrlChange, 100);
    };
    
    history.replaceState = function() {
        originalReplaceState.apply(this, arguments);
        setTimeout(checkUrlChange, 100);
    };
    
    // DOM changes
    if (document.body) {
        const observer = new MutationObserver(() => {
            clearTimeout(scanTimer);
            scanTimer = setTimeout(checkUrlChange, 1000);
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }
    
    // Message listener
    chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
        if (message.type === 'FORCE_SCAN') {
            console.log('Suraksha Kavach: Force scan requested');
            lastScannedUrl = ''; // Reset to force new scan
            performScan();
            sendResponse({ success: true });
        }
        return true;
    });
    
    console.log('Suraksha Kavach: Scanner initialized successfully');
    
})();
