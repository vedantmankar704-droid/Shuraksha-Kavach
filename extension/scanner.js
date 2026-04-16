// Suraksha Kavach Scanner - Enhanced Hostname Risk Scoring
(function() {
    'use strict';
    
    console.log('Suraksha Kavach: Scanner initializing - enhanced hostname risk scoring');
    
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
    
    // Normal words that should NOT trigger suspicion in trusted domains
    const TRUSTED_DOMAIN_NORMAL_WORDS = [
        'web', 'login', 'feed', 'account', 'chat', 'mail', 'help', 'support', 'api'
    ];
    
    // Suspicious phishing keywords
    const PHISHING_KEYWORDS = [
        'verify', 'bank', 'otp', 'password', 'secure', 
        'reward', 'free', 'account', 'update', 'claim', 'login'
    ];
    
    // Suspicious TLDs
    const SUSPICIOUS_TLDS = [
        '.xyz', '.top', '.support', '.click', '.live', '.free',
        '.tk', '.ml', '.ga', '.cf', '.work', '.date', '.download', '.info', '.biz', '.net'
    ];
    
    // Suspicious domain combinations (high risk)
    const SUSPICIOUS_DOMAIN_COMBINATIONS = [
        'free-reward', 'reward-free', 'free-update', 'update-free',
        'free-verify', 'verify-free', 'free-login', 'login-free',
        'free-bank', 'bank-free', 'free-otp', 'otp-free',
        'free-claim', 'claim-free', 'free-secure', 'secure-free',
        'reward-update', 'update-reward', 'reward-login', 'login-reward',
        'reward-verify', 'verify-reward', 'reward-bank', 'bank-reward'
    ];
    
    // Global state
    let lastScannedUrl = '';
    let scanTimer = null;
    let warningBanner = null;
    let isScanning = false;
    let lastScanTime = 0;
    
    // Enhanced function to check if domain is trusted (including subdomains)
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
    
    // Enhanced function to parse hostname components
    function parseHostname(hostname) {
        const parts = hostname.toLowerCase().split('.');
        
        return {
            full: hostname.toLowerCase(),
            base: parts.length >= 2 ? parts.slice(-2).join('.') : hostname.toLowerCase(),
            subdomain: parts.length > 2 ? parts.slice(0, -2).join('.') : '',
            tld: parts.length > 1 ? '.' + parts[parts.length - 1] : '',
            parts: parts,
            partCount: parts.length
        };
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
    
    // Enhanced function to detect suspicious hostname patterns with proper scoring
    function detectHostnamePatterns(hostname, trustInfo) {
        const patterns = {
            hasTooManyHyphens: false,
            hasChainedSecurityWords: false,
            hasRepeatedSecurityWords: false,
            hasMultiPartDomain: false,
            hasSuspiciousCombination: false,
            hyphenCount: 0,
            securityWordCount: 0,
            riskScore: 0,
            details: []
        };
        
        // Skip hostname pattern analysis for trusted domains
        if (trustInfo.trusted) {
            patterns.details.push('Trusted domain - hostname pattern analysis skipped');
            return patterns;
        }
        
        // Count hyphens in hostname (increased scoring)
        patterns.hyphenCount = (hostname.match(/-/g) || []).length;
        if (patterns.hyphenCount >= 1) {
            patterns.hasTooManyHyphens = true;
            // Enhanced scoring: 1 hyphen = +3, 2 hyphens = +8, 3+ hyphens = +15
            if (patterns.hyphenCount === 1) {
                patterns.riskScore += 3;
                patterns.details.push(`Single hyphen in hostname (${patterns.hyphenCount})`);
            } else if (patterns.hyphenCount === 2) {
                patterns.riskScore += 8;
                patterns.details.push(`Multiple hyphens in hostname (${patterns.hyphenCount})`);
            } else {
                patterns.riskScore += 15;
                patterns.details.push(`Excessive hyphens in hostname (${patterns.hyphenCount})`);
            }
        }
        
        // Split hostname into parts to analyze structure
        const hostnameParts = hostname.split(/[-.]/);
        
        // Check for chained security words (enhanced detection)
        const securityWordChains = [];
        let consecutiveSecurityWords = 0;
        let maxConsecutive = 0;
        
        for (const part of hostnameParts) {
            if (PHISHING_KEYWORDS.includes(part.toLowerCase())) {
                consecutiveSecurityWords++;
                maxConsecutive = Math.max(maxConsecutive, consecutiveSecurityWords);
                securityWordChains.push(part);
            } else {
                consecutiveSecurityWords = 0;
            }
            patterns.securityWordCount++;
        }
        
        // Enhanced scoring for chained security words
        if (maxConsecutive >= 2) {
            patterns.hasChainedSecurityWords = true;
            // Enhanced scoring: 2 consecutive = +12, 3+ consecutive = +20
            if (maxConsecutive === 2) {
                patterns.riskScore += 12;
                patterns.details.push(`Chained security words in hostname (${securityWordChains.join('-')})`);
            } else {
                patterns.riskScore += 20;
                patterns.details.push(`Multiple chained security words in hostname (${securityWordChains.join('-')})`);
            }
        }
        
        // Enhanced scoring for repeated security words
        if (patterns.securityWordCount >= 2) {
            patterns.hasRepeatedSecurityWords = true;
            // Enhanced scoring: 2 words = +8, 3 words = +15, 4+ words = +25
            if (patterns.securityWordCount === 2) {
                patterns.riskScore += 8;
                patterns.details.push(`Multiple security words in hostname (${patterns.securityWordCount})`);
            } else if (patterns.securityWordCount === 3) {
                patterns.riskScore += 15;
                patterns.details.push(`Many security words in hostname (${patterns.securityWordCount})`);
            } else {
                patterns.riskScore += 25;
                patterns.details.push(`Excessive security words in hostname (${patterns.securityWordCount})`);
            }
        }
        
        // Check for suspicious domain combinations (high risk)
        const hostnameLower = hostname.toLowerCase();
        for (const combo of SUSPICIOUS_DOMAIN_COMBINATIONS) {
            if (hostnameLower.includes(combo)) {
                patterns.hasSuspiciousCombination = true;
                patterns.riskScore += 15; // High risk score for suspicious combinations
                patterns.details.push(`Suspicious domain combination: ${combo}`);
                break; // Only add once
            }
        }
        
        // Check for multi-part domain names
        if (hostnameParts.length > 4) {
            patterns.hasMultiPartDomain = true;
            patterns.riskScore += 8;
            patterns.details.push(`Complex multi-part domain (${hostnameParts.length} parts)`);
        }
        
        // Add specific dangerous pattern detection
        if (hostnameLower.includes('login-verify-bank') || 
            hostnameLower.includes('verify-bank-login') ||
            hostnameLower.includes('bank-login-verify')) {
            patterns.riskScore += 20;
            patterns.details.push('Dangerous banking login pattern detected');
        }
        
        if (hostnameLower.includes('account-otp-update') ||
            hostnameLower.includes('otp-update-account') ||
            hostnameLower.includes('update-account-otp')) {
            patterns.riskScore += 18;
            patterns.details.push('Dangerous account verification pattern detected');
        }
        
        return patterns;
    }
    
    // Function to detect suspicious patterns in path
    function detectPathPatterns(pathname, trustInfo) {
        const patterns = {
            hasSuspiciousKeywords: false,
            hasExcessiveSegments: false,
            keywordCount: 0,
            keywordsFound: [],
            segmentCount: 0,
            riskScore: 0,
            details: []
        };
        
        // Reduce path analysis for trusted domains
        if (trustInfo.trusted) {
            patterns.riskScore = Math.max(0, patterns.riskScore - 2); // Minimal reduction
            patterns.details.push('Trusted domain - path analysis reduced');
        }
        
        // Count keywords in path
        const pathAnalysis = countPhishingKeywords(pathname);
        patterns.keywordCount = pathAnalysis.count;
        patterns.keywordsFound = pathAnalysis.found;
        
        if (patterns.keywordCount > 0) {
            patterns.hasSuspiciousKeywords = true;
            patterns.riskScore += patterns.keywordCount * 4; // Increased from 3
            patterns.details.push(`Suspicious keywords in path: ${patterns.keywordsFound.join(', ')}`);
        }
        
        // Count path segments
        patterns.segmentCount = pathname.split('/').filter(segment => segment.length > 0).length;
        if (patterns.segmentCount > 5) {
            patterns.hasExcessiveSegments = true;
            patterns.riskScore += 4; // Increased from 3
            patterns.details.push(`Excessive path segments (${patterns.segmentCount})`);
        }
        
        return patterns;
    }
    
    // Function to detect suspicious patterns in query parameters
    function detectQueryPatterns(search, trustInfo) {
        const patterns = {
            hasSuspiciousKeywords: false,
            hasExcessiveParams: false,
            hasRedirectTricks: false,
            keywordCount: 0,
            keywordsFound: [],
            paramCount: 0,
            riskScore: 0,
            details: []
        };
        
        if (!search || search.length === 0) {
            return patterns;
        }
        
        // Reduce query analysis for trusted domains
        if (trustInfo.trusted) {
            patterns.riskScore = Math.max(0, patterns.riskScore - 1); // Minimal reduction
            patterns.details.push('Trusted domain - query analysis reduced');
        }
        
        // Count keywords in query
        const queryAnalysis = countPhishingKeywords(search);
        patterns.keywordCount = queryAnalysis.count;
        patterns.keywordsFound = queryAnalysis.found;
        
        if (patterns.keywordCount > 0) {
            patterns.hasSuspiciousKeywords = true;
            patterns.riskScore += patterns.keywordCount * 3; // Increased from 2
            patterns.details.push(`Suspicious keywords in query: ${patterns.keywordsFound.join(', ')}`);
        }
        
        // Count parameters
        patterns.paramCount = search.split(/[&?]/).filter(param => param.length > 0).length;
        if (patterns.paramCount > 4) {
            patterns.hasExcessiveParams = true;
            patterns.riskScore += 4; // Increased from 3
            patterns.details.push(`Excessive query parameters (${patterns.paramCount})`);
        }
        
        // Check for redirect tricks
        if (search.toLowerCase().includes('redirect') || 
            search.toLowerCase().includes('url=') || 
            search.toLowerCase().includes('goto=')) {
            patterns.hasRedirectTricks = true;
            patterns.riskScore += 6; // Increased from 5
            patterns.details.push('Suspicious redirect parameters detected');
        }
        
        return patterns;
    }
    
    // Enhanced function to detect phishing indicators with improved scoring
    function detectUrlPhishingIndicators(urlStructure) {
        const indicators = {
            hostname: {},
            path: {},
            query: {},
            structural: {},
            riskScore: 0,
            allDetails: []
        };
        
        // Check if domain is trusted (including subdomains)
        const trustInfo = isTrustedDomain(urlStructure.hostname);
        console.log('Suraksha Kavach: Trust analysis for', urlStructure.hostname, '->', trustInfo);
        
        // Analyze hostname patterns (skip for trusted domains)
        indicators.hostname = detectHostnamePatterns(urlStructure.hostname, trustInfo);
        indicators.riskScore += indicators.hostname.riskScore;
        indicators.allDetails.push(...indicators.hostname.details);
        
        // Analyze path patterns (reduced for trusted domains)
        indicators.path = detectPathPatterns(urlStructure.pathname, trustInfo);
        indicators.riskScore += indicators.path.riskScore;
        indicators.allDetails.push(...indicators.path.details);
        
        // Analyze query patterns (reduced for trusted domains)
        indicators.query = detectQueryPatterns(urlStructure.search, trustInfo);
        indicators.riskScore += indicators.query.riskScore;
        indicators.allDetails.push(...indicators.query.details);
        
        // Structural analysis (always applies)
        const hostname = urlStructure.hostname;
        const hostnameParsed = parseHostname(hostname);
        
        // Suspicious TLDs
        const hasSuspiciousTld = SUSPICIOUS_TLDS.some(tld => hostname.toLowerCase().endsWith(tld));
        if (hasSuspiciousTld) {
            indicators.structural.suspiciousTld = true;
            indicators.riskScore += 10; // Increased from 8
            indicators.allDetails.push('Suspicious top-level domain');
        }
        
        // IP address
        const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        if (ipPattern.test(hostname)) {
            indicators.structural.ipAddress = true;
            indicators.riskScore += 30; // Increased from 25
            indicators.allDetails.push('IP address instead of domain');
        }
        
        // HTTP only (enhanced scoring)
        if (!urlStructure.fullUrl.startsWith('https://')) {
            indicators.structural.httpOnly = true;
            indicators.riskScore += 20; // Increased from 15
            indicators.allDetails.push('No HTTPS encryption');
        }
        
        // @ symbol
        if (urlStructure.fullUrl.includes('@')) {
            indicators.structural.atSymbol = true;
            indicators.riskScore += 15; // Increased from 12
            indicators.allDetails.push('@ symbol in URL');
        }
        
        // Very long URL
        if (urlStructure.fullUrl.length > 120) {
            indicators.structural.longUrl = true;
            indicators.riskScore += 8; // Increased from 6
            indicators.allDetails.push(`Very long URL (${urlStructure.fullUrl.length} chars)`);
        }
        
        // Add trust information to results
        indicators.trustInfo = trustInfo;
        
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
    
    // Main scanning function with enhanced scoring
    function performScan() {
        try {
            if (isScanning) {
                console.log('Suraksha Kavach: Scan already in progress');
                return;
            }
            
            const currentUrl = window.location.href;
            
            const now = Date.now();
            if (currentUrl === lastScannedUrl && (now - lastScanTime) < 3000) {
                console.log('Suraksha Kavach: Same URL, skipping scan');
                return;
            }
            
            console.log('Suraksha Kavach: Scanning URL:', currentUrl);
            isScanning = true;
            lastScannedUrl = currentUrl;
            
            // Analyze URL structure
            const urlStructure = analyzeUrlStructure(currentUrl);
            console.log('Suraksha Kavach: URL structure analyzed:', urlStructure);
            
            // Detect phishing indicators with enhanced scoring
            const phishingIndicators = detectUrlPhishingIndicators(urlStructure);
            console.log('Suraksha Kavach: Phishing indicators detected:', phishingIndicators);
            
            // Calculate final risk score with strong trust override
            let finalScore = phishingIndicators.riskScore;
            
            // Apply STRONG trusted domain override
            if (phishingIndicators.trustInfo.trusted) {
                console.log('Suraksha Kavach: Applying STRONG trusted domain override');
                finalScore = Math.max(0, Math.round(finalScore * 0.02)); // 98% reduction
                phishingIndicators.allDetails.push('Trusted domain - risk significantly reduced (98%)');
            }
            
            // Additional DOM analysis (minimal impact)
            let domAnalysisScore = 0;
            if (document.body) {
                const pageText = document.body.innerText.toLowerCase().substring(0, 3000);
                
                const passwordField = document.querySelector('input[type="password"]');
                if (passwordField) {
                    domAnalysisScore += 2;
                    phishingIndicators.allDetails.push('Password field detected');
                }
                
                const loginForm = document.querySelector('form');
                if (loginForm) {
                    domAnalysisScore += 1;
                    phishingIndicators.allDetails.push('Login form detected');
                }
                
                const pageKeywordAnalysis = countPhishingKeywords(pageText);
                if (pageKeywordAnalysis.count > 5) {
                    domAnalysisScore += pageKeywordAnalysis.count * 1;
                    phishingIndicators.allDetails.push('Multiple suspicious keywords in page content');
                }
            }
            
            // Final score calculation
            const totalScore = finalScore + domAnalysisScore;
            
            // Create result with trust information
            const result = {
                url: currentUrl,
                hostname: urlStructure.hostname,
                score: totalScore,
                reasons: phishingIndicators.allDetails,
                trustLevel: phishingIndicators.trustInfo.trusted ? 'trusted' : 'unknown',
                trustInfo: phishingIndicators.trustInfo,
                separatedAnalysis: {
                    hostname: phishingIndicators.hostname,
                    path: phishingIndicators.path,
                    query: phishingIndicators.query,
                    structural: phishingIndicators.structural
                },
                timestamp: Date.now()
            };
            
            console.log('Suraksha Kavach: Final scan result:', result);
            lastScanTime = now;
            
            // Show warning banner based on risk score
            if (totalScore >= 25) {
                showWarningBanner('high');
            } else if (totalScore >= 15) {
                showWarningBanner('medium');
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
    function showWarningBanner(level = 'high') {
        if (warningBanner) return;
        
        warningBanner = document.createElement('div');
        warningBanner.id = 'suraksha-warning-banner';
        
        const isHighRisk = level === 'high';
        const bgColor = isHighRisk ? '#d32f2f' : '#f57c00';
        const borderColor = isHighRisk ? '#b71c1c' : '#e65100';
        const title = isHighRisk ? 'PHISHING WARNING' : 'SECURITY WARNING';
        const message = isHighRisk ? 
            'This website shows strong signs of being a phishing attempt' :
            'This website shows some suspicious indicators';
        
        warningBanner.innerHTML = `
            <strong>${title}</strong><br>
            ${message}<br>
            <small>Do not enter passwords, OTP, or banking information</small>
        `;
        
        warningBanner.style.cssText = `
            position: fixed !important;
            top: 0 !important;
            left: 0 !important;
            width: 100% !important;
            background: ${bgColor} !important;
            color: white !important;
            padding: 15px 20px !important;
            text-align: center !important;
            font-family: Arial, sans-serif !important;
            font-size: 14px !important;
            font-weight: bold !important;
            z-index: 999999 !important;
            box-shadow: 0 4px 8px rgba(0,0,0,0.4) !important;
            border-bottom: 3px solid ${borderColor} !important;
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
    
    // URL change detection
    const checkUrlChange = throttle(function() {
        if (window.location.href !== lastScannedUrl) {
            console.log('Suraksha Kavach: URL change detected');
            clearTimeout(scanTimer);
            scanTimer = setTimeout(performScan, 500);
        }
    }, 1000);
    
    // Initialize
    console.log('Suraksha Kavach: Setting up enhanced hostname scoring for:', window.location.href);
    
    setTimeout(performScan, 500);
    setInterval(checkUrlChange, 1500);
    
    window.addEventListener('popstate', debounce(performScan, 300));
    
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
    
    chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
        if (message.type === 'FORCE_SCAN') {
            console.log('Suraksha Kavach: Force scan requested');
            lastScannedUrl = '';
            performScan();
            sendResponse({ success: true });
        }
        return true;
    });
    
    console.log('Suraksha Kavach: Enhanced hostname scoring scanner initialized successfully');
    
})();
