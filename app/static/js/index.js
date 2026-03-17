document.addEventListener('DOMContentLoaded', function() {
    // Sidebar toggle
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('main-content');
    const toggleBtn = document.getElementById('sidebar-toggle');

    if (toggleBtn) {
        // Restore collapsed state from localStorage
        if (localStorage.getItem('sidebar-collapsed') === 'true') {
            sidebar.classList.add('collapsed');
            mainContent.classList.add('expanded');
        }

        toggleBtn.addEventListener('click', function() {
            sidebar.classList.toggle('collapsed');
            mainContent.classList.toggle('expanded');
            localStorage.setItem('sidebar-collapsed', sidebar.classList.contains('collapsed'));
        });
    }

    // Copy URL buttons
    document.querySelectorAll('.copy-url-btn').forEach(function(button) {
        button.addEventListener('click', function() {
            copyToClipboard(this);
        });
    });

    // Resizable columns
    initResizableTable('edl-table');
});

function copyToClipboard(clickedElement) {
    const urlToCopy = clickedElement.getAttribute('data-url');
    const fullURL = urlToCopy.endsWith('/') ? urlToCopy : urlToCopy + '/';

    if (navigator.clipboard) {
        navigator.clipboard.writeText(fullURL).then(function() {
            showConfirmation(clickedElement.nextElementSibling);
        }).catch(function(error) {
            console.error('Copy failed:', error);
        });
    }
}

function showConfirmation(element) {
    if (!element) return;
    element.style.display = 'inline';
    element.style.opacity = '1';
    setTimeout(function() {
        element.style.opacity = '0';
        setTimeout(function() {
            element.style.display = 'none';
        }, 600);
    }, 2000);
}

function deleteRecord(itemId, event) {
    const confirmBox = document.createElement('div');
    confirmBox.id = 'confirmBox';
    confirmBox.className = 'confirm-dialog';
    confirmBox.innerHTML =
        '<p style="margin-bottom:8px">Are you sure?</p>' +
        '<button class="btn btn-sm btn-outline-danger me-1" onclick="sendDeleteRequest(' + itemId + ')">Yes</button>' +
        '<button class="btn btn-sm btn-outline-secondary" onclick="this.parentNode.remove()">No</button>';
    confirmBox.style.position = 'absolute';
    confirmBox.style.left = event.clientX + 'px';
    confirmBox.style.top = event.clientY + 'px';
    confirmBox.style.backgroundColor = '#fff';
    confirmBox.style.border = '1px solid #e0e2e8';
    confirmBox.style.padding = '12px';
    confirmBox.style.borderRadius = '8px';
    confirmBox.style.boxShadow = '0 4px 12px rgba(0,0,0,0.15)';
    confirmBox.style.textAlign = 'center';
    confirmBox.style.zIndex = '9999';

    // Remove existing confirm box
    var existing = document.getElementById('confirmBox');
    if (existing) existing.remove();

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
    }).then(function(response) {
        if (response.ok) {
            var box = document.getElementById('confirmBox');
            if (box) box.remove();
            window.location.reload(true);
        }
    }).catch(function(error) {
        console.error('Network error:', error);
    });
}

// Resizable table columns with localStorage persistence
function initResizableTable(tableId) {
    var table = document.getElementById(tableId);
    if (!table) return;

    var storageKey = 'col-widths-' + tableId;
    var headers = table.querySelectorAll('thead th');
    var defaultWidths = [15, 30, 35, 20];

    // Restore saved widths or use defaults
    var saved = localStorage.getItem(storageKey);
    var widths = saved ? JSON.parse(saved) : defaultWidths;

    // Apply widths
    headers.forEach(function(th, i) {
        if (widths[i]) th.style.width = widths[i] + '%';
    });

    // Add resize handles
    headers.forEach(function(th, i) {
        if (i === headers.length - 1) return; // no handle on last column

        var handle = document.createElement('div');
        handle.className = 'col-resize-handle';
        th.appendChild(handle);

        var startX, startWidth, nextStartWidth, tableWidth;

        handle.addEventListener('mousedown', function(e) {
            e.preventDefault();
            startX = e.pageX;
            tableWidth = table.offsetWidth;
            startWidth = th.offsetWidth;
            nextStartWidth = headers[i + 1].offsetWidth;
            handle.classList.add('active');

            function onMouseMove(e) {
                var diff = e.pageX - startX;
                var newWidth = startWidth + diff;
                var newNextWidth = nextStartWidth - diff;

                // Minimum 40px per column
                if (newWidth < 40 || newNextWidth < 40) return;

                var pct = (newWidth / tableWidth) * 100;
                var nextPct = (newNextWidth / tableWidth) * 100;
                th.style.width = pct + '%';
                headers[i + 1].style.width = nextPct + '%';
            }

            function onMouseUp() {
                handle.classList.remove('active');
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);

                // Save all column widths
                var currentWidths = [];
                headers.forEach(function(h) {
                    currentWidths.push(parseFloat(((h.offsetWidth / table.offsetWidth) * 100).toFixed(2)));
                });
                localStorage.setItem(storageKey, JSON.stringify(currentWidths));
            }

            document.addEventListener('mousemove', onMouseMove);
            document.addEventListener('mouseup', onMouseUp);
        });
    });
}
