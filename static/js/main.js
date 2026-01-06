document.addEventListener('DOMContentLoaded', function() {

   
    var alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        
        if (alert.classList.contains('alert-success') || alert.classList.contains('alert-danger')) {
            setTimeout(function() {
                
                alert.classList.remove('show');
               
                setTimeout(function() {
                    alert.remove();
                }, 150);
            }, 4000);
        }
    });

    
    var deleteLinks = document.querySelectorAll('.btn-danger');
    deleteLinks.forEach(function(btn) {
        btn.addEventListener('click', function(e) {
            
            if (btn.tagName === 'A') {
                var confirmed = confirm('Are you sure you want to delete this? This cannot be undone.');
                if (!confirmed) {
                    e.preventDefault(); 
                }
            }
        });
    });

    
    
    var forms = document.querySelectorAll('form');
    forms.forEach(function(form) {
        form.addEventListener('submit', function() {
            var btn = form.querySelector('button[type="submit"]');
            if (btn) {
                
                var originalText = btn.innerHTML;
                
                btn.innerHTML = 'Processing...';
                btn.style.opacity = '0.7';
                
            }
        });
    });

});