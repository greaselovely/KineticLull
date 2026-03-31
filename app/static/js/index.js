document.addEventListener('DOMContentLoaded', function() {
    // Sidebar toggle
    var sidebar = document.getElementById('sidebar');
    var mainContent = document.getElementById('main-content');
    var toggleBtn = document.getElementById('sidebar-toggle');
    var html = document.documentElement;

    if (toggleBtn) {
        // Sync element classes with the <html> state set in <head>
        if (html.classList.contains('sidebar-is-collapsed')) {
            sidebar.classList.add('collapsed');
            mainContent.classList.add('expanded');
        }

        toggleBtn.addEventListener('click', function() {
            sidebar.classList.toggle('collapsed');
            mainContent.classList.toggle('expanded');
            html.classList.toggle('sidebar-is-collapsed');
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

    // Admin submenu toggle
    var adminToggle = document.getElementById('admin-menu-toggle');
    var adminSubmenu = document.getElementById('admin-submenu');
    if (adminToggle && adminSubmenu) {
        // Sync with <html> state
        if (html.classList.contains('admin-menu-is-open')) {
            adminSubmenu.classList.add('open');
            adminToggle.classList.add('open');
        }
        adminToggle.addEventListener('click', function(e) {
            e.preventDefault();
            adminSubmenu.classList.toggle('open');
            adminToggle.classList.toggle('open');
            html.classList.toggle('admin-menu-is-open');
            localStorage.setItem('admin-menu-open', adminSubmenu.classList.contains('open'));
        });
    }

    // System submenu toggle
    var systemToggle = document.getElementById('system-menu-toggle');
    var systemSubmenu = document.getElementById('system-submenu');
    if (systemToggle && systemSubmenu) {
        if (localStorage.getItem('system-menu-open') === 'true') {
            systemSubmenu.classList.add('open');
            systemToggle.classList.add('open');
        }
        systemToggle.addEventListener('click', function(e) {
            e.preventDefault();
            systemSubmenu.classList.toggle('open');
            systemToggle.classList.toggle('open');
            localStorage.setItem('system-menu-open', systemSubmenu.classList.contains('open'));
        });
    }

    // Favorite toggle
    document.querySelectorAll('.favorite-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var itemId = this.getAttribute('data-id');
            var icon = this;
            var csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
            fetch('favorite/' + itemId + '/', {
                method: 'POST',
                headers: { 'X-CSRFToken': csrfToken }
            }).then(function(r) { return r.json(); }).then(function(data) {
                if (data.favorited) {
                    icon.classList.remove('bi-star');
                    icon.classList.add('bi-star-fill', 'text-warning');
                } else {
                    icon.classList.remove('bi-star-fill', 'text-warning');
                    icon.classList.add('bi-star');
                }
            });
        });
    });
});

function copyToClipboard(clickedElement) {
    const urlToCopy = clickedElement.getAttribute('data-url');
    const fullURL = urlToCopy.endsWith('/') ? urlToCopy : urlToCopy + '/';

    if (navigator.clipboard) {
        navigator.clipboard.writeText(fullURL).then(function() {
            showCopyFlash(clickedElement);
        }).catch(function(error) {
            console.error('Copy failed:', error);
        });
    }
}

function showCopyFlash(element) {
    var star = document.createElement('i');
    star.className = 'bi bi-star-fill';
    star.style.cssText = 'color: #ffc107; font-size: 1rem; position: absolute; margin-left: -8px; margin-top: -4px; pointer-events: none; transition: opacity 0.3s;';
    element.parentNode.style.position = 'relative';
    element.parentNode.appendChild(star);
    setTimeout(function() {
        star.style.opacity = '0';
        setTimeout(function() { star.remove(); }, 300);
    }, 700);
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

function sendDeleteRequest(itemId, force) {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    var body = { 'id': itemId };
    if (force) body.force = true;
    fetch('delete/' + itemId + '/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify(body)
    }).then(function(response) {
        if (response.ok) {
            var box = document.getElementById('confirmBox');
            if (box) box.remove();
            window.location.reload(true);
        } else if (response.status === 409) {
            var box = document.getElementById('confirmBox');
            if (box) box.remove();
            response.json().then(function(data) {
                showProtectedDeleteModal(itemId, data);
            });
        }
    }).catch(function(error) {
        console.error('Network error:', error);
    });
}

function showProtectedDeleteModal(itemId, data) {
    // Remove existing modal if any
    var existing = document.getElementById('protectedDeleteModal');
    if (existing) existing.remove();

    var modal = document.createElement('div');
    modal.id = 'protectedDeleteModal';
    modal.className = 'modal fade';
    modal.tabIndex = -1;
    modal.innerHTML =
        '<div class="modal-dialog">' +
        '  <div class="modal-content">' +
        '    <div class="modal-header">' +
        '      <h5 class="modal-title text-danger"><i class="bi bi-exclamation-triangle me-2"></i>Active EDL</h5>' +
        '      <button type="button" class="btn-close" data-bs-dismiss="modal"></button>' +
        '    </div>' +
        '    <div class="modal-body">' +
        '      <p><strong>' + data.edl_name + '</strong> was accessed <strong>' + data.access_count +
        '      </strong> time' + (data.access_count !== 1 ? 's' : '') + ' in the last <strong>' +
        data.window_minutes + '</strong> minutes.</p>' +
        '      <p class="text-muted small">This EDL appears to be actively polled by a firewall. Deleting it may break firewall policy.</p>' +
        '      <label class="form-label">Type <strong>' + data.edl_name + '</strong> to confirm deletion:</label>' +
        '      <input type="text" class="form-control form-control-sm" id="protectedDeleteConfirmInput" autocomplete="off">' +
        '    </div>' +
        '    <div class="modal-footer">' +
        '      <button type="button" class="btn btn-sm btn-secondary" data-bs-dismiss="modal">Cancel</button>' +
        '      <button type="button" class="btn btn-sm btn-danger" id="protectedDeleteConfirmBtn" disabled>Delete</button>' +
        '    </div>' +
        '  </div>' +
        '</div>';

    document.body.appendChild(modal);

    var bsModal = new bootstrap.Modal(modal);
    bsModal.show();

    var input = document.getElementById('protectedDeleteConfirmInput');
    var btn = document.getElementById('protectedDeleteConfirmBtn');

    input.addEventListener('input', function() {
        btn.disabled = input.value !== data.edl_name;
    });

    btn.addEventListener('click', function() {
        bsModal.hide();
        sendDeleteRequest(itemId, true);
    });

    modal.addEventListener('hidden.bs.modal', function() {
        modal.remove();
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
