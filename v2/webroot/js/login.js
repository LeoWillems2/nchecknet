        const loginForm = document.getElementById('loginForm');
        const messageDiv = document.getElementById('message');
        serverUrl = String(window.location);
	if ( serverUrl.slice(-1) === '/'){
		serverUrl = serverUrl.substr(0,serverUrl.length-1);
	}

        // Helper function to display messages
        function displayMessage(text, type) {
            messageDiv.textContent = text;
            messageDiv.className = type;
        }

        // --- Login Function ---
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(loginForm);
            const data = Object.fromEntries(formData.entries());

            try {
                // We must add {credentials: 'include'} so the browser sends any existing cookie
                // and, more importantly, accepts the 'Set-Cookie' header from the server response.
                const response = await fetch(`${serverUrl}/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(data),
                    credentials: 'include' 
                });

                if (response.ok) {
                    const resultText = await response.text();
                    // The server response says: "Login successful. JWT set in HTTP-only cookie."
                    displayMessage(`SUCCESS: ${resultText}`, 'success');
		    window.location.assign("main.html");
		    //await accessProtected();
                } else {
                    const errorText = await response.text();
                    displayMessage(`LOGIN FAILED (${response.status}): ${errorText}`, 'error');
                }
            } catch (error) {
                displayMessage(`Network Error: ${error.message}`, 'error');
            }
        });
