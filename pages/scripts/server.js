function send_code(mail, code) {
    return new Promise(function (resolve, reject) {
        $.ajax({
            dataType: 'json',
        
            url: 'https://212.233.76.232:5000/api/code-confirm',
            type: 'POST', 
            contentType: 'application/json', 
            data: JSON.stringify({
                data: {
                    code: code,
                    mail: mail,
                },
            }),

            success: function(response) {
                alert(response['response']);
                if (response['response'] == 'Mail verified') resolve(true);
                else resolve(false);
            },
            
            error: function(error) {
                console.error('Error: ', error);
                reject(error);
            },
        });
    });
}

function generate_code(mail) {
    return new Promise((resolve, reject) => {
        $.ajax({
            dataType: 'json',
            url: 'https://212.233.76.232:5000/api/mail-confirm',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                data: {
                    mail: mail
                },
            }),

            success: function (response) {
                alert(response['response']);
                if (response['response'] !== 'Bad mail') resolve(true);
                else resolve(false);
            },

            error: function (error) {
                console.error('Error: ', error);
                reject(error);
            },
        });
    });
}