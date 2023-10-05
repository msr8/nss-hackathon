function login() {
    const url = '/api/login';
    const username_input = document.getElementById('username_input');
    const password_input = document.getElementById('password_input');

    const form_data = new FormData();
    form_data.append('username', username_input.value); // Change 'username' to 'email'
    form_data.append('password', password_input.value);

    const requestOptions = {
        method: "POST",
        body: form_data,
    };

    fetch(url, requestOptions)
        .then(response => response.json())
        .then(data => {
            console.log(data);
            // If status is 200, redirect to /
            if (data.status === 200) {window.location.href = '/';}
            // Else, display error message
            else {alert(data.message);}
        })
        .catch(error => {
            console.error('Fetch error:', error);
        });
}


