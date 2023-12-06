var current_user = null;

class User {
	constructor(login, admin_status) {
		this.login = login;
		this.admin_status = admin_status;
	}
}

function registerUser(login, admin_status) {
    var currentUser = new User(login, admin_status);
    localStorage.setItem('current_user', JSON.stringify(currentUser));
}

function loadCurrentUser() {
    var storedUser = localStorage.getItem('current_user');

    if (storedUser) {
        current_user = JSON.parse(storedUser);
    }
}