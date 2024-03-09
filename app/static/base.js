$(document).ready(function() {
    $('.heart-icon').click(function() {
        var postId = $(this).data('post-id');
        if (postId) {
            $.ajax({
                url: '/like/' + postId,
                type: 'POST',
                success: function(response) {

                    // Updating the heart icon
                    var heartIcon = $('img.heart-icon[data-post-id="' + postId + '"]');
                    heartIcon.attr('src', response.is_liked ? '/static/RedHeart.png' : '/static/BlackHeart.png');

                    // Corrected selector for likesCountElement
                    var likesCountElement = heartIcon.closest('.card-footer').find('.heart-count');

                    likesCountElement.text(response.likes_count);
                },
                error: function() {
                    alert('Error liking the post.');
                }
            });
        } else {
            console.error('Post ID is undefined.');
        }
    });
});