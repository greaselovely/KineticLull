// API key show/hide + copy. Only present on the user form when a key exists,
// so every lookup is guarded.
(function () {
    var toggle = document.getElementById('toggle-api-key-visibility');
    var copyBtn = document.getElementById('copy-api-key');
    var apiKeyElement = document.getElementById('api-key');
    if (!apiKeyElement) return;

    if (toggle) {
        toggle.addEventListener('click', function () {
            var hidden = apiKeyElement.classList.toggle('blur-text');
            apiKeyElement.classList.toggle('unblur-text', !hidden);
            toggle.className = 'bi ' + (hidden ? 'bi-eye' : 'bi-eye-slash') + ' action-items';
        });
    }

    if (copyBtn) {
        copyBtn.addEventListener('click', function () {
            var apiKey = apiKeyElement.innerText;
            var done = function () { flashCopied(copyBtn); };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(apiKey).then(done, done);
            } else {
                var ta = document.createElement('textarea');
                ta.value = apiKey; document.body.appendChild(ta); ta.select();
                document.execCommand('copy'); document.body.removeChild(ta); done();
            }
        });
    }
})();
