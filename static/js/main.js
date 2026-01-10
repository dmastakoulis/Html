document.addEventListener('DOMContentLoaded', function() {

    // 1. Alert Auto-Dismiss
    // This works with the manual alerts you added in the Register page
    var alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        // Only auto-dismiss success messages, keep errors visible so users can read them
        if (alert.classList.contains('alert-success')) {
            setTimeout(function() {
                alert.style.transition = "opacity 0.5s ease";
                alert.style.opacity = "0";
                setTimeout(function() {
                    alert.remove();
                }, 500);
            }, 3000);
        }
    });

    // 2. Delete Confirmation (Fixed for your Checkbox Forms)
    var deleteForms = document.querySelectorAll('form[action*="delete"]');
    deleteForms.forEach(function(form) {
        form.addEventListener('submit', function(e) {
            // Check if any checkboxes are actually selected
            var checkboxes = form.querySelectorAll('input[type="checkbox"]:checked');
            
            // If checkboxes exist but none are checked, alert the user
            var allCheckboxes = form.querySelectorAll('input[type="checkbox"]');
            if (allCheckboxes.length > 0 && checkboxes.length === 0) {
                e.preventDefault();
                alert('Please select at least one item to delete.');
                return;
            }

            // If items are selected, ask for confirmation
            var count = checkboxes.length > 0 ? checkboxes.length : 'this';
            var confirmed = confirm('Are you sure you want to delete ' + count + ' item(s)? This cannot be undone.');
            
            if (!confirmed) {
                e.preventDefault(); // Stop if they say Cancel
            }
        });
    });

    // 3. Button Loading State (Works with btn-figma)
    var forms = document.querySelectorAll('form');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(e) {
            // Don't change button if the form was prevented (e.g. by the delete confirm above)
            if (e.defaultPrevented) return;

            var btn = form.querySelector('button[type="submit"]');
            if (btn) {
                var originalText = btn.innerText;
                // Store original text so we could technically restore it if needed
                btn.dataset.originalText = originalText;
                
                btn.innerHTML = 'Processing...';
                btn.style.opacity = '0.7';
                btn.style.pointerEvents = 'none'; // Prevent double-clicking
            }
        });
    });

});
