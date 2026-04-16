// Suraksha Kavach Scanner - Enhanced with Trusted Domain Logic
(function() {
    'use strict';
    
    console.log('Suraksha Kavach: Scanner initializing - with trusted domains');
    
    // Trusted domains whitelist
    const TRUSTED_DOMAINS = [
        'github.com',
        'google.com',
        'chatgpt.com', 
        'openai.com',
        'microsoft.com',
        'gmail.com',
        'facebook.com',
        'twitter.com',
        'linkedin.com',
        'stackoverflow.com',
        'youtube.com',
        'wikipedia.org',
        'reddit.com'
    ];
    
    // Global state
    let lastScannedUrl = '';
    let scanTimer = null;
    let warningBanner = null;
    let isScanning = false;
    let lastScanTime = 0;
    
    // Function to check if domain is trusted
    function isTrustedDomain(hostname) {
        return TRUSTED_DOMAINS.some(trusted => {
            // Exact match
            if (hostname === trusted) return true;
            // Subdomain match
            if (hostname.endsWith('.' + trusted)) return true;
            return false;
        });
    }
    
    // Function to get domain trust level
    function getTrustLevel(hostname) {
        if (isTrustedDomain(hostname)) {
            return 'trusted';
        }
        return 'unknown';
    }
    
    // Debounce function for performance
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
    
    // Throttle function for rapid events
    function throttle(func, limit) {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }
    
    // Main scanning function with trusted domain logic
    function performScan() {
        try {
            // Prevent multiple simultaneous scans
            if (isScanning) {
                console.log('Suraksha Kavach: Scan already in progress');
                return;
            }
            
            const currentUrl = window.location.href;
            const hostname = window.location.hostname;
            
            // Skip if same URL and recent scan
            const now = Date.now();
            if (currentUrl === lastScannedUrl && (now - lastScanTime) < 5000) {
                console.log('Suraksha Kavach: Same URL, skipping scan');
                return;
            }
            
            console.log('Suraksha Kavach: Scanning URL:', currentUrl, 'Domain:', hostname);
            isScanning = true;
            lastScannedUrl = currentUrl;
            
            // Check trust level first
            const trustLevel = getTrustLevel(hostname);
            const isTrusted = trustLevel === 'trusted';
            
            // Optimized page text extraction
            const pageText = document.body ? 
                document.body.innerText.toLowerCase().substring(0, 10000) : '';
            
            // Calculate risk score with trusted domain logic
            let score = 0;
            const reasons = [];
            
            // TRUSTED DOMAIN LOGIC - Significantly reduce risk
            if (isTrusted) {
                console.log('Suraksha Kavach: Trusted domain detected, applying reduced scoring');
                
                // For trusted domains, only apply critical security checks
                // Rule 1: HTTP instead of HTTPS (still important)
                if (!currentUrl.startsWith('https://')) {
                    score += 5; // Reduced from 20 to 5
                    reasons.push('No HTTPS encryption (reduced risk for trusted domain)');
                }
                
                // Rule 2: URL length > 75 (less concerning for trusted sites)
                if (currentUrl.length > 75) {
                    score += 3; // Reduced from 15 to 3
                    reasons.push('Long URL detected (reduced risk for trusted domain)');
                }
                
                // Rule 3: Suspicious keywords - IGNORE for trusted domains
                // Skip keyword detection entirely for trusted domains
                console.log('Suraksha Kavach: Skipping keyword detection for trusted domain');
                
                // Rule 4: Password field - very low risk for trusted domains
                const passwordField = document.querySelector('input[type="password"]');
                if (passwordField) {
                    score += 2; // Reduced from 15 to 2
                    reasons.push('Password field detected (normal for trusted domain)');
                }
                
                // Rule 5: Login form - very low risk for trusted domains
                const loginForm = document.querySelector('form');
                if (loginForm) {
                    score += 1; // Reduced from 10 to 1
                    reasons.push('Login form detected (normal for trusted domain)');
                }
                
            } else {
                // UNKNOWN DOMAIN LOGIC - Apply full security checks
                console.log('Suraksha Kavach: Unknown domain, applying full security scoring');
                
                // Rule 1: HTTP instead of HTTPS
                if (!currentUrl.startsWith('https://')) {
                    score += 20;
                    reasons.push('No HTTPS encryption');
                }
                
                // Rule 2: URL length > 75
                if (currentUrl.length > 75) {
                    score += 15;
                    reasons.push('Long URL detected');
                }
                
                // Rule 3: Hostname contains hyphen
                if (hostname.includes('-')) {
                    score += 10;
                    reasons.push('Hyphenated domain');
                }
                
                // Rule 4: Suspicious keywords (each +10) - only for unknown domains
                const suspiciousKeywords = [
                    'verify', 'otp', 'bank', 'urgent', 'password', 'login'
                ];
                
                for (const keyword of suspiciousKeywords) {
                    if (pageText.includes(keyword)) {
                        score += 10;
                        reasons.push(`Suspicious keyword: "${keyword}"`);
                    }
                }
                
                // Rule 5: Password input field (+15)
                const passwordField = document.querySelector('input[type="password"]');
                if (passwordField) {
                    score += 15;
                    reasons.push('Password field detected');
                }
                
                // Rule 6: Login form (+10)
                const loginForm = document.querySelector('form');
                if (loginForm) {
                    score += 10;
                    reasons.push('Login form detected');
                }
            }
            
            // Additional security checks (apply to all, but reduced for trusted)
            const ipMultiplier = isTrusted ? 0.2 : 1.0; // 80% reduction for trusted
            
            // IP address in domain
            const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
            if (ipPattern.test(hostname)) {
                score += Math.round(30 * ipMultiplier);
                reasons.push('IP address instead of domain' + (isTrusted ? ' (reduced risk)' : ''));
            }
            
            // Suspicious TLDs
            const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click'];
            if (suspiciousTlds.some(tld => hostname.endsWith(tld))) {
                score += Math.round(25 * ipMultiplier);
                reasons.push('Suspicious top-level domain' + (isTrusted ? ' (reduced risk)' : ''));
            }
            
            // Final score adjustment for trusted domains
            if (isTrusted && score > 0) {
                // Additional reduction for trusted domains
                score = Math.max(0, Math.round(score * 0.3)); // 70% reduction
                reasons.push('Trusted domain - risk significantly reduced');
            }
            
            // Create result
            const result = {
                url: currentUrl,
                hostname: hostname,
                score: score,
                reasons: reasons,
                trustLevel: trustLevel,
                timestamp: Date.now()
            };
            
            console.log('Suraksha Kavach: Scan result:', result);
            lastScanTime = now;
            
            // Show warning banner if risky (higher threshold for trusted domains)
            const warningThreshold = isTrusted ? 40 : 20; // Higher threshold for trusted
            if (score >= warningThreshold) {
                showWarningBanner();
            } else {
                hideWarningBanner();
            }
            
            // Send to background with optimized messaging
            chrome.runtime.sendMessage({
                type: 'PHISH_SCAN_RESULT',
                payload: result
            }, function(response) {
                isScanning = false; // Reset scanning flag
                if (chrome.runtime.lastError) {
                    console.error('Suraksha Kavach: Message error:', chrome.runtime.lastError);
                } else {
                    console.log('Suraksha Kavach: Message sent successfully');
                }
            });
            
        } catch (error) {
            isScanning = false;
            console.error('Suraksha Kavach: Scan error:', error);
        }
    }
    
    // Warning banner functions (optimized)
    function showWarningBanner() {
        if (warningBanner) return; // Already showing
        
        warningBanner = document.createElement('div');
        warningBanner.id = 'suraksha-warning-banner';
        warningBanner.innerHTML = `
            ⚠ Warning: This website may be suspicious<br>
            Do not enter password / OTP / bank details
        `;
        
        // Apply warning banner styles
        warningBanner.style.cssText = `
            position: fixed !important;
            top: 0 !important;
            left: 0 !important;
            width: 100% !important;
            background: #d32f2f !important;
            color: white !important;
            padding: 12px 20px !important;
            text-align: center !important;
            font-family: Arial, sans-serif !important;
            font-size: 14px !important;
            font-weight: bold !important;
            z-index: 999999 !important;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3) !important;
            border-bottom: 2px solid #b71c1c !important;
            line-height: 1.4 !important;
            animation: slideDown 0.3s ease-out !important;
        `;
        
        // Insert at the beginning of body
        if (document.body) {
            document.body.insertBefore(warningBanner, document.body.firstChild);
            
            // Push content down only if needed
            const currentMargin = document.body.style.marginTop;
            if (!currentMargin || currentMargin === '0px' || currentMargin === '') {
                document.body.style.marginTop = '60px';
            }
        }
    }
    
    function hideWarningBanner() {
        if (warningBanner) {
            warningBanner.style.animation = 'slideUp 0.3s ease-out';
            setTimeout(() => {
                if (warningBanner) {
                    warningBanner.remove();
                    warningBanner = null;
                    
                    // Reset body margin
                    if (document.body) {
                        document.body.style.marginTop = '';
                    }
                }
            }, 300);
        }
    }
    
    // Optimized URL change detection
    const checkUrlChange = throttle(function() {
        if (window.location.href !== lastScannedUrl) {
            console.log('Suraksha Kavach: URL change detected');
            clearTimeout(scanTimer);
            scanTimer = setTimeout(performScan, 500); // Reduced delay
        }
    }, 1000);
    
    // Initialize
    console.log('Suraksha Kavach: Setting up scanner with trusted domains for:', window.location.href);
    
    // Initial scan with reduced delay
    setTimeout(performScan, 500);
    
    // Optimized periodic checks
    setInterval(checkUrlChange, 1500); // Reduced from 2000ms
    
    // Navigation events
    window.addEventListener('popstate', debounce(performScan, 300));
    
    // SPA navigation with debouncing
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;
    
    history.pushState = debounce(function() {
        originalPushState.apply(this, arguments);
        setTimeout(checkUrlChange, 100);
    }, 200);
    
    history.replaceState = debounce(function() {
        originalReplaceState.apply(this, arguments);
        setTimeout(checkUrlChange, 100);
    }, 200);
    
    // Optimized DOM changes
    if (document.body) {
        const observer = new MutationObserver(debounce(() => {
            clearTimeout(scanTimer);
            scanTimer = setTimeout(checkUrlChange, 800); // Reduced delay
        }, 500));
        
        observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: false,
            attributeOldValue: false,
            characterData: false
        });
    }
    
    // Optimized message listener
    chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
        if (message.type === 'FORCE_SCAN') {
            console.log('Suraksha Kavach: Force scan requested');
            lastScannedUrl = ''; // Reset to force new scan
            performScan();
            sendResponse({ success: true });
        }
        return true;
    });
    
    console.log('Suraksha Kavach: Scanner with trusted domain logic initialized successfully');
    
})();
