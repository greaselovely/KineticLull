
document.addEventListener('DOMContentLoaded', (event) => {
    document.querySelectorAll('.copy-url-btn').forEach(button => {
        button.addEventListener('click', function() {
            const urlToCopy = this.getAttribute('data-url');
            navigator.clipboard.writeText(urlToCopy).then(() => {
                showCopyConfirmation(this.nextElementSibling);
            }).catch(err => {
                console.error('Could not copy text: ', err);
            });
        });
    });
});

function showCopyConfirmation(confirmationElement) {
    confirmationElement.style.display = 'inline';
    confirmationElement.style.opacity = '1';

    setTimeout(() => {
        confirmationElement.style.opacity = '0'; 
        setTimeout(() => {
            confirmationElement.style.display = 'none';
        }, 600); // Duration of fade-out
    }, 2000); // Display time before fading
}




function editItem(itemId) {
    console.log('Edit item ID:', itemId);
}

function copyItem(url, event) {
    const fullURL = url + '/';

    if (navigator.clipboard) {
        navigator.clipboard.writeText(fullURL)
            .then(() => {
                console.log('URL copied:', fullURL);
                showCopiedMessage(event);
            })
            .catch((error) => {
                console.error('Copy failed:', error);
            });
    } else {
        // Fallback method for non-secure contexts
        const textArea = document.createElement('textarea');
        textArea.value = fullURL;
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();

        try {
            const successful = document.execCommand('copy');
            const msg = successful ? 'successful' : 'unsuccessful';
            console.log('Fallback: Copying text command was ' + msg);
            showCopiedMessage(event);
        } catch (err) {
            console.error('Fallback: Oops, unable to copy', err);
        }

        document.body.removeChild(textArea);
    }
}

function showCopiedMessage(event) {
    let message = document.createElement('div');
    message.innerText = 'Copied!';
    message.style.position = 'absolute';
    message.style.left = (event.clientX + 20) + 'px';
    message.style.top = (event.clientY + 20) + 'px';
    message.style.backgroundColor = '#000';
    message.style.color = '#fff';
    message.style.padding = '5px 10px';
    message.style.borderRadius = '5px';
    message.style.fontSize = '12px';
    message.style.fontFamily = 'Arial, sans-serif';
    message.style.zIndex = '1000';
    message.style.pointerEvents = 'none';

    document.body.appendChild(message);

    setTimeout(() => {
        if (message.parentNode) {
            message.parentNode.removeChild(message);
        }
    }, 2000);
}

function download_edl(friendlyName, ipFqdnStr) {
    const ipFqdnArray = ipFqdnStr.split('\r\n');
    const textContent = ipFqdnArray.join('\n');
    const blob = new Blob([textContent], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const filename = `${friendlyName}.txt`;
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
}

function deleteRecord(itemId, event) {
    const confirmBox = document.createElement('div');
    confirmBox.innerHTML = `
        <p>Are you sure you want to delete this item?</p>
        <button onclick="sendDeleteRequest(${itemId})">Yes, delete it</button>
        <button onclick="this.parentNode.remove()">Cancel</button>
    `;
    confirmBox.style.position = 'absolute';
    confirmBox.style.left = `${event.clientX}px`;
    confirmBox.style.top = `${event.clientY}px`;
    confirmBox.style.backgroundColor = '#fff';
    confirmBox.style.border = '1px solid #ccc';
    confirmBox.style.padding = '10px';
    confirmBox.style.borderRadius = '5px';
    confirmBox.style.boxShadow = '0 2px 5px rgba(0,0,0,0.2)';
    confirmBox.id = 'confirmBox';
    document.body.appendChild(confirmBox);
}

function sendDeleteRequest(itemId) {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    fetch('delete/' + itemId + '/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({ 'id': itemId })
    }).then(response => {
        if (response.ok) {
            document.getElementById('confirmBox')?.remove();
            location.reload();
        }
    });
}

function deleteRecord(itemId, event) {
    const confirmBox = document.createElement('div');
    confirmBox.innerHTML = `
        <p>Are you sure?</p>
        <button id="confirmYes" onclick="sendDeleteRequest(${itemId})">Yes</button>
        <button id="confirmNo" onclick="this.parentNode.remove()">No</button>
    `;
    confirmBox.style.position = 'absolute';
    confirmBox.style.left = `${event.clientX}px`;
    confirmBox.style.top = `${event.clientY}px`;
    confirmBox.style.backgroundColor = '#fff';
    confirmBox.style.border = '1px solid #ccc';
    confirmBox.style.padding = '10px';
    confirmBox.style.borderRadius = '5px';
    confirmBox.style.boxShadow = '0 2px 5px rgba(0,0,0,0.2)';
    confirmBox.style.textAlign = 'center';
    confirmBox.id = 'confirmBox';

    // Styling for the buttons
    const buttons = confirmBox.querySelectorAll('button');
    buttons.forEach(button => {
        button.style.border = 'none';
        button.style.padding = '1px 1px';
        button.style.margin = '1px';
        button.style.borderRadius = '2px';
        button.style.cursor = 'pointer';
        button.style.backgroundColor = '#f0f0f0';
        button.style.boxShadow = '0 2px 4px rgba(0,0,0,0.1)';
        button.addEventListener('mouseover', () => button.style.backgroundColor = '#e0e0e0');
        button.addEventListener('mouseout', () => button.style.backgroundColor = '#f0f0f0');
    });

    // Specific styling for Yes button
    const yesButton = confirmBox.querySelector('#confirmYes');
    yesButton.style.backgroundColor = '#fff';
    yesButton.style.color = '#000';
    yesButton.addEventListener('mouseover', () => yesButton.style.backgroundColor = '#000');
    yesButton.addEventListener('mouseover', () => yesButton.style.color = '#fff');
    yesButton.addEventListener('mouseout', () => yesButton.style.backgroundColor = '#fff');
    yesButton.addEventListener('mouseout', () => yesButton.style.color = '#000');

    // Specific styling for No button
    const noButton = confirmBox.querySelector('#confirmNo');
    noButton.style.backgroundColor = '#fff';
    noButton.style.color = '#000';
    noButton.addEventListener('mouseover', () => noButton.style.backgroundColor = '#000');
    noButton.addEventListener('mouseover', () => noButton.style.color = '#fff');
    noButton.addEventListener('mouseout', () => noButton.style.backgroundColor = '#fff');
    noButton.addEventListener('mouseout', () => noButton.style.color = '#000');

    document.body.appendChild(confirmBox);
}

function sendDeleteRequest(itemId) {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    fetch('delete/' + itemId + '/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({ 'id': itemId })
    }).then(response => {
        console.log('Server response:', response);
        if (response.ok) {
            document.getElementById('confirmBox')?.remove();
            reloadPage();
        } else {
            console.log("Something is b0rk3n")
            // reloadPage();
        }
    }).catch(error => {
        // Handle network errors
        console.error('Network error:', error);
        alert('Network error, please try again.');
    });
}

function reloadPage() {
    window.location.reload(true);
}
