// Auto-refresh dashboard
if (window.location.pathname === '/dashboard' || window.location.pathname === '/') {
    setTimeout(() => {
        window.location.reload();
    }, 5000);
}

// Autocomplete for Item Search
document.addEventListener('DOMContentLoaded', () => {
    const itemInput = document.getElementById('item_id');
    if (itemInput) {
        // Create a wrapper for the input to position the dropdown
        const wrapper = document.createElement('div');
        wrapper.style.position = 'relative';
        itemInput.parentNode.insertBefore(wrapper, itemInput);
        wrapper.appendChild(itemInput);

        const dropdown = document.createElement('div');
        dropdown.className = 'autocomplete-dropdown';
        dropdown.style.display = 'none';
        dropdown.style.position = 'absolute';
        dropdown.style.width = '100%';
        dropdown.style.maxHeight = '200px';
        dropdown.style.overflowY = 'auto';
        dropdown.style.backgroundColor = 'white';
        dropdown.style.border = '1px solid #ddd';
        dropdown.style.zIndex = '1000';
        wrapper.appendChild(dropdown);

        let debounceTimer;

        itemInput.addEventListener('input', (e) => {
            clearTimeout(debounceTimer);
            const q = e.target.value;

            if (q.length < 1) {
                dropdown.style.display = 'none';
                return;
            }

            debounceTimer = setTimeout(() => {
                fetch(`/api/items/search?q=${q}`)
                    .then(res => res.json())
                    .then(data => {
                        dropdown.innerHTML = '';
                        if (data.results.length > 0) {
                            dropdown.style.display = 'block';
                            data.results.forEach(item => {
                                const div = document.createElement('div');
                                div.textContent = item.text;
                                div.style.padding = '8px';
                                div.style.cursor = 'pointer';
                                div.style.borderBottom = '1px solid #eee';

                                div.addEventListener('click', () => {
                                    itemInput.value = item.id; // Set ID
                                    // Optionally show name in a separate field or replace input
                                    dropdown.style.display = 'none';
                                });

                                div.addEventListener('mouseover', () => {
                                    div.style.backgroundColor = '#f0f0f0';
                                });
                                div.addEventListener('mouseout', () => {
                                    div.style.backgroundColor = 'white';
                                });

                                dropdown.appendChild(div);
                            });
                        } else {
                            dropdown.style.display = 'none';
                        }
                    });
            }, 300);
        });

        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (e.target !== itemInput) {
                dropdown.style.display = 'none';
            }
        });
    }
});

// Location Details Modal
const modal = document.getElementById("locationModal");
const span = document.getElementsByClassName("close")[0];

if (span) {
    span.onclick = function () {
        modal.style.display = "none";
    }
}

window.onclick = function (event) {
    if (event.target == modal) {
        modal.style.display = "none";
    }
}

function showLocationDetails(id, name) {
    const modal = document.getElementById("locationModal");
    const title = document.getElementById("modalLocationName");
    const content = document.getElementById("modalContent");

    modal.style.display = "block";
    title.textContent = name;
    content.innerHTML = 'Loading...';

    fetch(`/api/location/${id}/inventory`)
        .then(response => response.json())
        .then(data => {
            if (data.inventory.length === 0) {
                content.innerHTML = '<p>No items in this location.</p>';
                return;
            }

            let html = '<table class="modal-table"><thead><tr><th>Item</th><th>SKU</th><th>Brand</th><th>Qty</th><th>Packing</th><th>Plts</th><th>Expiry</th><th>Date</th><th>User</th></tr></thead><tbody>';
            data.inventory.forEach(item => {
                const expiryClass = checkExpiryJS(item.expiry);
                html += `<tr>
                    <td style="font-weight:600;">${item.item_name}</td>
                    <td>${item.item_sku}</td>
                    <td>${item.brand || '-'}</td>
                    <td style="font-weight:bold; color: var(--primary);">${item.quantity}</td>
                    <td>${item.packing || '-'}</td>
                    <td>${item.pallets || '-'}</td>
                    <td class="expiry-${expiryClass}">${item.expiry || '-'}</td>
                    <td>${item.date || '-'}</td>
                    <td>${item.worker_name || '-'}</td>
                </tr>`;
            });
            html += '</tbody></table>';
            content.innerHTML = html;
        })
        .catch(err => {
            content.innerHTML = '<p>Error loading details.</p>';
            console.error(err);
        });
}

function checkExpiryJS(expiryStr) {
    if (!expiryStr) return '';
    try {
        const parts = expiryStr.split('/');
        if (parts.length !== 2) return '';
        const month = parseInt(parts[0], 10);
        let year = parseInt(parts[1], 10);

        // Handle 2-digit year assumption (20xx)
        if (year < 100) year += 2000;

        // Compare with today
        const today = new Date();
        const currentYear = today.getFullYear();
        const currentMonth = today.getMonth() + 1; // 0-indexed

        // Construct expiry date (End of month? or Start?)
        // Python logic used Start of Month logic for simplicity or Next Month 1st - 1 day.
        // Let's mirror Python: Expired if today > last day of expiry month.
        // Last day of expiry month:
        const nextMonth = month === 12 ? 1 : month + 1;
        const nextMonthYear = month === 12 ? year + 1 : year;
        const lastDayOfExpiry = new Date(nextMonthYear, nextMonth - 1, 0); // Day 0 of next month = last day of prev

        if (today > lastDayOfExpiry) return 'expired';

        // Check for "expiring soon" (60 days)
        const diffTime = lastDayOfExpiry - today;
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

        if (diffDays < 60) return 'expiring';

        return 'ok';
    } catch (e) {
        return '';
    }
}

function showToast(message, type = 'success') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.position = 'fixed';
        container.style.bottom = '20px';
        container.style.right = '20px';
        container.style.zIndex = '9999';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.textContent = message;
    toast.style.background = type === 'error' ? 'var(--danger, #ef4444)' : 'var(--success, #10b981)';
    toast.style.color = 'white';
    toast.style.padding = '12px 24px';
    toast.style.borderRadius = '8px';
    toast.style.marginBottom = '10px';
    toast.style.boxShadow = '0 4px 6px rgba(0,0,0,0.1)';
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s ease';

    container.appendChild(toast);

    requestAnimationFrame(() => {
        toast.style.opacity = '1';
    });

    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// --- Keyboard Shortcuts ---
document.addEventListener('keydown', function (e) {
    // 1. CTRL+S to Save
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        if (typeof finishBatch === 'function') {
            finishBatch();
            showToast('Saving Batch...', 'success');
        }
        return;
    }

    // 2. Navigation (Enter & Arrows)
    const inputs = Array.from(document.querySelectorAll('input:not([type="hidden"]), select, button:not([tabindex="-1"])'));
    if (inputs.length === 0) return;

    const active = document.activeElement;
    const index = inputs.indexOf(active);

    if (index > -1) {
        // ENTER -> Move Next
        if (e.key === 'Enter') {
            if (active.tagName === 'BUTTON') return;
            e.preventDefault();
            const next = inputs[index + 1];
            if (next) next.focus();
        }

        // ARROWS
        if (['ArrowDown', 'ArrowRight'].includes(e.key)) {
            if (active.tagName === 'SELECT' && !e.altKey) return;
            const next = inputs[index + 1];
            if (next) next.focus();
        }
        if (['ArrowUp', 'ArrowLeft'].includes(e.key)) {
            if (active.tagName === 'SELECT' && !e.altKey) return;
            const prev = inputs[index - 1];
            if (prev) prev.focus();
        }
    }
});
