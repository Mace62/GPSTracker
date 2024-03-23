
console.log("JavaScript is linked!");




document.addEventListener('DOMContentLoaded', function () {
    var selectionFormElement = document.getElementById('{{ selection_form.group.id }}');
    if (selectionFormElement) {
        selectionFormElement.onchange = function () {
            var groupId = this.value;
            if (groupId === '') {
                window.location.href = '/group';
            } else if (groupId) {
                window.location.href = '/group/' + groupId;
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
    $('body').on('submit', 'form.ajax-deny-request', function (e) {
        e.preventDefault();
        var form = $(this);
        var url = form.attr('action');  // Ensure this URL is correctly set to your Flask route for denying requests
        var data = form.serialize();

        $.ajax({
            type: 'POST',
            url: url,  // This should correctly point to '/deny_friend_request_ajax/<request_id>'
            data: data,
            success: function (response) {
                if (response.status === 'success') {
                    $('div.card[data-user-id="' + response.deniedUserId + '"]').remove();
                    $('form[data-user-id="' + response.deniedUserId + '"]')
                        .removeClass('ajax-cancel-request').addClass('ajax-friend-request')
                        .attr('action', '/send_friend_request/' + response.deniedUserId)  // Adjust if needed based on Flask `url_for`
                        .html('<button type="submit" class="btn btn-primary">Add Friend</button>');
                }
            },
            error: function (xhr) {
                console.error("Error: " + xhr.responseText);
            }
        });
    });

});