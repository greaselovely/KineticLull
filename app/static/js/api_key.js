document.getElementById('toggle-api-key-visibility').addEventListener('click', function() {
    var apiKeyElement = document.getElementById('api-key');
    if (apiKeyElement.classList.contains('blur-text')) {
        apiKeyElement.classList.remove('blur-text');
        apiKeyElement.classList.add('unblur-text');
    } else {
        apiKeyElement.classList.add('blur-text');
        apiKeyElement.classList.remove('unblur-text');
    }
});

document.getElementById('copy-api-key').addEventListener('click', function() {
    var apiKey = document.getElementById('api-key').innerText;
    var trigger = this;
    navigator.clipboard.writeText(apiKey).then(function() {
        showCopyFlash(trigger);
    }, function(err) {
        console.error('Could not copy text: ', err);
    });
});
