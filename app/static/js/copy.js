document.getElementById('copy-api-key').addEventListener('click', function() {
    var apiKey = document.getElementById('api-key').innerText;
    navigator.clipboard.writeText(apiKey).then(function() {
        showCopyConfirmation();
    }, function(err) {
        console.error('Could not copy text: ', err);
    });
});

function showCopyConfirmation() {
    const confirmation = document.getElementById('copy-confirmation');
    confirmation.style.display = 'inline';
    confirmation.style.opacity = '1';

    setTimeout(() => {
        confirmation.style.opacity = '0'; 
        setTimeout(() => {
            confirmation.style.display = 'none';
        }, 600); // Duration of fade out
    }, 2000); // Display time before fading
}
