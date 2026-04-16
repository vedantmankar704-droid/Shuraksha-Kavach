// Suraksha Kavach Scanner - Critical Phishing Detection Fix
(function() {
    'use strict';
    
    console.log('Suraksha Kavach: Scanner initializing - critical phishing detection');
    
    // STRICT exact-match trusted domains whitelist only
    const TRUSTED_DOMAINS = [
        'github.com',
        'google.com',
        'openai.com',
        'chatgpt.com'
    ];
    
    // Suspicious phishing keywords
    const PHISHING_KEYWORDS = [
        'login', 'verify', 'bank', 'otp', 'password', 'secure', 
        'reward', 'free', 'account', 'update', 'claim'
    ];
    
    // Global state
    let lastScannedUrl = '';
    let scanTimer = null;
    let warningBanner = null;
    let isScanning = false;
    let lastScanTime = 0;
    
    // Function to check if domain is EXACTLY trusted (no subdomains)
    function isExactTrustedDomain(hostname) {
        return TRUSTED_DOMAINS.includes(hostname);
    }
    
    // Function to extract URL components for analysis
    function analyzeUrlStructure(url) {
        try {
            const urlObj = new URL(url);
            return {
                hostname: urlObj.hostname,
                pathname: urlObj.pathname,
                search: urlObj.search,
                fullUrl: url
            };
        } catch (error) {
            console.error('URL parsing error:', error);
            return {
                hostname: '',
                pathname: '',
                search: '',
                fullUrl: url
            };
        }
    }
    
    // Function to count suspicious keywords in text
    function countPhishingKeywords(text) {
        const lowerText = text.toLowerCase();
        const found = [];
        let count = 0;
        
        for (const keyword of PHISHING_KEYWORDS) {
            if (lowerText.includes(keyword)) {
                count++;
                found.push(keyword);
            }
        }
        
        return { count, found };
    }
    
    // Function to detect phishing indicators in URL structure
    function detectUrlPhishingIndicators(urlStructure) {
        const indicators = {
            suspiciousKeywords: { count: 0, found: [], locations: [] },
            structuralIssues: [],
            riskScore: 0
        };
        
        // Analyze hostname for suspicious keywords
        const hostnameAnalysis = countPhishingKeywords(urlStructure.hostname);
        if (hostnameAnalysis.count > 0) {
            indicators.suspiciousKeywords.count += hostnameAnalysis.count;
            indicators.suspiciousKeywords.found.push(...hostnameAnalysis.found);
            indicators.suspiciousKeywords.locations.push(`hostname: ${hostnameAnalysis.found.join(', ')}`);
            indicators.riskScore += hostnameAnalysis.count * 15; // Keywords in hostname are very suspicious
        }
        
        // Analyze pathname for suspicious keywords
        const pathnameAnalysis = countPhishingKeywords(urlStructure.pathname);
        if (pathnameAnalysis.count > 0) {
            indicators.suspiciousKeywords.count += pathnameAnalysis.count;
            indicators.suspiciousKeywords.found.push(...pathnameAnalysis.found);
            indicators.suspiciousKeywords.locations.push(`path: ${pathnameAnalysis.found.join(', ')}`);
            indicators.riskScore += pathnameAnalysis.count * 10; // Keywords in path are suspicious
        }
        
        // Analyze query parameters for suspicious keywords
        const searchAnalysis = countPhishingKeywords(urlStructure.search);
        if (searchAnalysis.count > 0) {
            indicators.suspiciousKeywords.count += searchAnalysis.count;
            indicators.suspiciousKeywords.found.push(...searchAnalysis.found);
            indicators.suspiciousKeywords.locations.push(`query: ${searchAnalysis.found.join(', ')}`);
            indicators.riskScore += searchAnalysis.count * 8; // Keywords in query are suspicious
        }
        
        // Structural analysis
        const hostname = urlStructure.hostname;
        
        // Multiple hyphens in hostname
        const hyphenCount = (hostname.match(/-/g) || []).length;
        if (hyphenCount > 2) {
            indicators.structuralIssues.push(`Multiple hyphens in hostname (${hyphenCount})`);
            indicators.riskScore += hyphenCount * 5;
        }
        
        // Multiple subdomains
        const subdomainCount = hostname.split('.').length - 2;
        if (subdomainCount > 2) {
            indicators.structuralIssues.push(`Multiple subdomains (${subdomainCount})`);
            indicators.riskScore += subdomainCount * 8;
        }
        
        // Long hostname
        if (hostname.length > 50) {
            indicators.structuralIssues.push(`Long hostname (${hostname.length} chars)`);
            indicators.riskScore += 10;
        }
        
        // Long URL overall
        if (urlStructure.fullUrl.length > 100) {
            indicators.structuralIssues.push(`Long URL (${urlStructure.fullUrl.length} chars)`);
            indicators.riskScore += 8;
        }
        
        // Suspicious TLDs
        const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click', '.free', '.net', '.work'];
        const hasSuspiciousTld = suspiciousTlds.some(tld => hostname.toLowerCase().endsWith(tld));
        if (hasSuspiciousTld) {
            indicators.structuralIssues.push('Suspicious top-level domain');
            indicators.riskScore += 25;
        }
        
        // IP address in hostname
        const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        if (ipPattern.test(hostname)) {
            indicators.structuralIssues.push('IP address instead of domain');
            indicators.riskScore += 30;
        }
        
        // HTTP instead of HTTPS
        if (!urlStructure.fullUrl.startsWith('https://')) {
            indicators.structuralIssues.push('No HTTPS encryption');
            indicators.riskScore += 20;
        }
        
        // @ symbol in URL
        if (urlStructure.fullUrl.includes('@')) {
            indicators.structuralIssues.push('@ symbol in URL');
            indicators.riskScore += 15;
        }
        
        return indicators;
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
    
    // Main scanning function with URL structure analysis
    function performScan() {
        try {
            // Prevent multiple simultaneous scans
            if (isScanning) {
                console.log('Suraksha Kavach: Scan already in progress');
                return;
            }
            
            const currentUrl = window.location.href;
            
            // Skip if same URL and recent scan
            const now = Date.now();
            if (currentUrl === lastScannedUrl && (now - lastScanTime) < 3000) {
                console.log('Suraksha Kavach: Same URL, skipping scan');
                return;
            }
            
            console.log('Suraksha Kavach: Scanning URL:', currentUrl);
            isScanning = true;
            lastScannedUrl = currentUrl;
            
            // Analyze URL structure FIRST (before DOM content)
            const urlStructure = analyzeUrlStructure(currentUrl);
            console.log('Suraksha Kavach: URL structure analyzed:', urlStructure);
            
            // Check if domain is EXACTLY trusted
            const isExactTrusted = isExactTrustedDomain(urlStructure.hostname);
            console.log('Suraksha Kavach: Domain trust check:', urlStructure.hostname, '->', isExactTrusted);
            
            // Detect phishing indicators from URL structure
            const phishingIndicators = detectUrlPhishingIndicators(urlStructure);
            console.log('Suraksha Kavach: Phishing indicators detected:', phishingIndicators);
            
            // Calculate final risk score
            let finalScore = phishingIndicators.riskScore;
            let reasons = [];
            
            // Add reasons from URL analysis
            if (phishingIndicators.suspiciousKeywords.count > 0) {
                reasons.push(`Suspicious keywords found: ${phishingIndicators.suspiciousKeywords.found.join(', ')}`);
                reasons.push(`Keywords in: ${phishingIndicators.suspiciousKeywords.locations.join('; ')}`);
            }
            
            reasons.push(...phishingIndicators.structuralIssues);
            
            // Apply trust reduction ONLY for exact matches
            if (isExactTrusted) {
                console.log('Suraksha Kavach: Applying trusted domain reduction for EXACT match');
                finalScore = Math.max(0, Math.round(finalScore * 0.1)); // 90% reduction for exact trusted domains
                reasons.push('Exact trusted domain - risk significantly reduced');
            }
            // NO reduction for unknown domains or subdomains
            
            // Additional DOM-based analysis (only if needed)
            let domAnalysisScore = 0;
            if (document.body) {
                const pageText = document.body.innerText.toLowerCase().substring(0, 5000);
                
                // Password field detection
                const passwordField = document.querySelector('input[type="password"]');
                if (passwordField) {
                    domAnalysisScore += 5;
                    reasons.push('Password field detected');
                }
                
                // Login form detection
                const loginForm = document.querySelector('form');
                if (loginForm) {
                    domAnalysisScore += 3;
                    reasons.push('Login form detected');
                }
                
                // Additional keywords in page content (lower weight)
                const pageKeywordAnalysis = countPhishingKeywords(pageText);
                if (pageKeywordAnalysis.count > 3) {
                    domAnalysisScore += pageKeywordAnalysis.count * 2;
                    reasons.push(`Multiple suspicious keywords in page content`);
                }
            }
            
            // Final score calculation
            const totalScore = finalScore + domAnalysisScore;
            
            // Create result
            const result = {
                url: currentUrl,
                hostname: urlStructure.hostname,
                score: totalScore,
                reasons: reasons,
                trustLevel: isExactTrusted ? 'trusted' : 'unknown',
                urlAnalysis: {
                    suspiciousKeywordCount: phishingIndicators.suspiciousKeywords.count,
                    suspiciousKeywords: phishingIndicators.suspiciousKeywords.found,
                    structuralIssues: phishingIndicators.structuralIssues,
                    isExactTrusted: isExactTrusted
                },
                timestamp: Date.now()
            };
            
            console.log('Suraksha Kavach: Final scan result:', result);
            lastScanTime = now;
            
            // Show warning banner if risky
            if (totalScore >= 20) {
                showWarningBanner();
            } else {
                hideWarningBanner();
            }
            
            // Send to background
            chrome.runtime.sendMessage({
                type: 'PHISH_SCAN_RESULT',
                payload: result
            }, function(response) {
                isScanning = false;
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
    
    // Warning banner functions
    function showWarningBanner() {
        if (warningBanner) return;
        
        warningBanner = document.createElement('div');
        warningBanner.id = 'suraksha-warning-banner';
        warningBanner.innerHTML = `
            <strong>PHISHING WARNING</strong><br>
            This website shows strong signs of being a phishing attempt<br>
            <small>Do not enter passwords, OTP, or banking information</small>
        `;
        
        warningBanner.style.cssText = `
            position: fixed !important;
            top: 0 !important;
            left: 0 !important;
            width: 100% !important;
            background: #d32f2f !important;
            color: white !important;
            padding: 15px 20px !important;
            text-align: center !important;
            font-family: Arial, sans-serif !important;
            font-size: 14px !important;
            font-weight: bold !important;
            z-index: 999999 !important;
            box-shadow: 0 4px 8px rgba(0,0,0,0.4) !important;
            border-bottom: 3px solid #b71c1c !important;
            line-height: 1.4 !important;
            animation: slideDown 0.3s ease-out !important;
        `;
        
        if (document.body) {
            document.body.insertBefore(warningBanner, document.body.firstChild);
            
            const currentMargin = document.body.style.marginTop;
            if (!currentMargin || currentMargin === '0px' || currentMargin === '') {
                document.body.style.marginTop = '80px';
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
            scanTimer = setTimeout(performScan, 500);
        }
    }, 1000);
    
    // Initialize
    console.log('Suraksha Kavach: Setting up critical phishing detection for:', window.location.href);
    
    // Initial scan with reduced delay
    setTimeout(performScan, 500);
    
    // Optimized periodic checks
    setInterval(checkUrlChange, 1500);
    
    // Navigation events
    window.addEventListener('popstate', debounce(performScan, 300));
    
    // SPA navigation
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
    
    // DOM changes
    if (document.body) {
        const observer = new MutationObserver(debounce(() => {
            clearTimeout(scanTimer);
            scanTimer = setTimeout(checkUrlChange, 800);
        }, 500));
        
        observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: false,
            attributeOldValue: false,
            characterData: false
        });
    }
    
    // Message listener
    chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
        if (message.type === 'FORCE_SCAN') {
            console.log('Suraksha Kavach: Force scan requested');
            lastScannedUrl = '';
            performScan();
            sendResponse({ success: true });
        }
        return true;
    });
    
    console.log('Suraksha Kavach: Critical phishing detection scanner initialized successfully');
    
})();
