if (window.location.hostname === 'mail.google.com') {
    if (typeof initGmailAnalysis === 'function') {
        initGmailAnalysis();
    }
} else {
    if (typeof initUrlAnalysis === 'function') {
        initUrlAnalysis();
    }
}
