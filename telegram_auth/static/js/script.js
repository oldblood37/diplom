document.addEventListener('DOMContentLoaded', function() {
    var authorizeButton = document.getElementById('authorizeButton');
    authorizeButton.addEventListener('click', authorize);
});

function authorize() {
    var authCode = document.getElementById('authCode').value;

    fetch('/telegram_auth/check-code/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken')
        },
        body: JSON.stringify({ code: authCode })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            window.location.href = `/telegram_auth/user-page/?userId=${data.userId}`;
        } else {
            document.getElementById('message').innerText = data.message;
        }
    })
    .catch(error => {
        console.error('Ошибка:', error);
        document.getElementById('message').innerText = 'Ошибка связи с сервером';
    });
}

function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}
