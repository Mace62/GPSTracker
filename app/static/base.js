
console.log("JavaScript is linked!");




document.addEventListener('DOMContentLoaded', function () {
    var selectionFormElement = document.getElementById('{{ selection_form.group.id }}');
    if (selectionFormElement) {
        selectionFormElement.onchange = function () {
            var groupId = this.value;
            if (groupId === '') {
                window.location.href = '/group';
            } else if (groupId) {
                window.location.href = '/viewgroup/' + groupId;
            }
        };
    }

    document.querySelectorAll('.friend-card').forEach(card => {
        card.addEventListener('click', function () {
            this.classList.toggle('selected');
            updateSelectedFriends();
        });
    });

    function updateSelectedFriends() {
        const selectedIds = Array.from(document.querySelectorAll('.friend-card.selected')).map(card => card.dataset.id);
        document.querySelector('input[name="selected_friends"]').value = selectedIds.join(',');
    }
});


$(document).ready(function () {
    var csrf_token = $('meta[name=csrf-token]').attr('content');

    $.ajaxSetup({
        beforeSend: function (xhr, settings) {
            if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
                xhr.setRequestHeader("X-CSRFToken", csrf_token);
            }
        }
    });

    // Use event delegation for dynamically added '.ajax-friend-request' forms
    $('body').on('submit', 'form.ajax-friend-request', function (e) {
        e.preventDefault();
        var form = $(this);
        submitAjaxForm(form);
    });

    // Use event delegation for dynamically added '.ajax-cancel-request' forms
    $('body').on('submit', 'form.ajax-cancel-request', function (e) {
        e.preventDefault();
        var form = $(this);
        submitAjaxForm(form);
    });

    function submitAjaxForm(form) {
        var url = form.attr('action');
        var data = form.serialize();
        $.ajax({
            type: 'POST',
            url: url,
            data: data,
            success: function (response) {
                // Assuming response contains a newAction attribute indicating the next action URL
                // and optionally, a newRequestID if the action requires a specific friend request ID
                if (form.hasClass('ajax-friend-request')) {
                    form.removeClass('ajax-friend-request').addClass('ajax-cancel-request')
                        .html('<button type="submit" class="btn btn-secondary">Sent Request</button>');
                    // Update form action to cancel request, use response.newAction
                    form.attr('action', response.newAction);
                } else if (form.hasClass('ajax-cancel-request')) {
                    form.removeClass('ajax-cancel-request').addClass('ajax-friend-request')
                        .html('<button type="submit" class="btn btn-primary">Add Friend</button>');
                    // Update form action to send friend request, use response.newAction
                    form.attr('action', response.newAction);
                }
            },
            error: function (xhr) {
                var response = JSON.parse(xhr.responseText);
                alert(response.message);
            }
        });


    }
    $(document).ready(function () {

        var friendIdToRemove = null; // Variable to store the friend ID to remove

        // When a "Remove Friend" button is clicked, show the modal and store the friend ID
        $('body').on('click', '.remove-friend-btn', function () {
            friendIdToRemove = $(this).data('friend-id'); // Store the friend ID
            $('#myModal').show(); // Show the modal
        });

        // When the "Confirm Remove" button in the modal is clicked
        $('#confirmRemove').off('click').on('click', function () {
            if (friendIdToRemove !== null) {
                var url = '/remove_friend/' + friendIdToRemove; // Construct the URL for removal
                // Perform the AJAX request to remove the friend
                $.ajax({
                    type: 'POST',
                    url: url,
                    // Make sure to include CSRF token if needed
                    success: function (response) {
                        $('#myModal').hide(); // Hide the modal on success
                        // Optionally, update the UI to reflect the removal
                        $('div#friend-' + friendIdToRemove).remove(); // Remove the friend from the UI
                        // Reset any related forms in the search results back to "Add Friend"
                        resetFormToFriendState(friendIdToRemove);
                        friendIdToRemove = null; // Reset the stored friend ID
                    },
                    error: function (xhr) {
                        var response = JSON.parse(xhr.responseText);
                        alert(response.message);
                        $('#myModal').hide(); // Optionally hide the modal on error
                    }
                });
            }
        });

        // Handle the "Cancel" button click in the modal
        $('#cancelRemove').click(function () {
            $('#myModal').hide(); // Hide the modal
        });

        // Handle clicking on the modal's close button
        $('.close').click(function () {
            $('#myModal').hide();
        });
    });

    // Function to reset any related forms in the search results back to "Add Friend"
    function resetFormToFriendState(friendId) {
        $('form[data-friend-id="' + friendId + '"]').each(function () {
            var $form = $(this);
            var username = $form.data('username');
            // Reset the form to "Add Friend" state
            $form.removeClass('ajax-cancel-request').addClass('ajax-friend-request');
            $form.attr('action', '/send_friend_request/' + username);
            $form.html('<button type="submit" class="btn btn-primary">Add Friend</button>');
        });
    }

});


