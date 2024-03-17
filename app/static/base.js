

document.addEventListener('DOMContentLoaded', function() {
    document.querySelector('.toggle-form').addEventListener('click', function(event) {
        var formContainer = document.getElementById('group-creation-form');
        
        // Toggle form visibility
        if (formContainer.style.display === 'none' || formContainer.style.display === '') {
            formContainer.style.display = 'block'; // Show form
            event.target.textContent = 'Cancel'; // Optional: Change button text
        } else {
            formContainer.style.display = 'none'; // Hide form
            event.target.textContent = 'Create New Group'; // Optional: Reset button text
        }
    });
});








$(document).ready(function() {
    $('#group-creation-form').on('submit', function(e) {
        e.preventDefault(); // Prevent the default form submission
        var formData = $(this).serialize(); // Serialize the form data
        
        $.ajax({
            url: '/path/to/your/form/processing', // The URL to process the form submission
            type: 'POST',
            data: formData,
            success: function(response) {
                // Handle success (e.g., display a success message, hide the form)
                $('#group-creation-form').hide();
                $('.toggle-form').text('Create New Group');
                // Optionally, display a success message to the user
            },
            error: function(xhr, status, error) {
                // Handle errors (e.g., display error messages to the user)
            }
        });
    });
});

