function newAcc() {

    var userEmail = document.getElementById("email").value;
    var userPass = document.getElementById("pass").value;
    var name = document.getElementById("name").value;

    if (userEmail != "" && userPass != "" && name != "") {
        var mailformat = /^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{1,5}|[0-9]{1,3})(\]?)$/;
        var btn = document.getElementById("btn");
        var ic = document.getElementById("ic");

        var win = document.getElementById("note");
        var mess = document.getElementById("msg");

        if (userEmail.match(mailformat)) {
            ic.classList.add("fa");
            ic.classList.add("fa-spinner");
            ic.classList.add("fa-spin");
            firebase.auth().createUserWithEmailAndPassword(userEmail, userPass).then(cred => {

                //Start test DB
                cred.user.updateProfile({
                    displayName: name
                    //photoURL: "https://example.com/jane-q-user/profile.jpg"
                })
                    .then(function () {
                        //console.log("Document successfully written!");
                        var mail = document.getElementById("email").value;
                        var text = "Your account was successfully created <br> A verification link was sent to " + mail;
                        mess.innerHTML = text;
                        win.classList.add('fadeIn');
                        win.style.display = "block";
                    })
                    .catch(function (error) {
                        //console.error("Error writing document: ", error);
                        document.getElementById('name').disabled = false;
                        document.getElementById('email').disabled = false;
                        document.getElementById('pass').disabled = false;

                        mess.textContent = "An error occured, however, your account was succesfully created";
                        win.classList.add('fadeIn');
                        win.style.display = "block";
                    });
                //End DB test
                //mess.textContent = "Your account was successfully created";
                //win.classList.add('fadeIn');
                //win.style.display = "block";
                //win.display.visibility = "visible";

            }).catch(function (error) {
                document.getElementById('name').disabled = false;
                document.getElementById('email').disabled = false;
                document.getElementById('pass').disabled = false;

                mess.textContent = error;
                win.classList.add('fadeIn');
                win.style.display = "block";
                //win.display.visibility = "visible";
                btn.disabled = false;
                check = false;
            })
        }
        else {
            document.getElementById('name').disabled = false;
            document.getElementById('email').disabled = false;
            document.getElementById('pass').disabled = false;

            mess.textContent = "Email address format is incorrect";
            win.classList.add('fadeIn');
            win.style.display = "block";
        }
    }
}

function login() {
    var userEmail = document.getElementById("email").value;
    var userPass = document.getElementById("pass").value;

    if (userEmail != "" && userPass != "") {
        var mailformat = /^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{1,5}|[0-9]{1,3})(\]?)$/;
        var btn = document.getElementById("btn");
        var ic = document.getElementById("ic");

        var win = document.getElementById("note");
        var mess = document.getElementById("msg");

        if (userEmail.match(mailformat)) {
            ic.classList.add("fa");
            ic.classList.add("fa-spinner");
            ic.classList.add("fa-spin");

            firebase.auth().signInWithEmailAndPassword(userEmail, userPass).then(({ user }) => {
                    return user.getIdToken().then((idToken) => {
                        return fetch("/loginsession", {
                            method: "POST",
                            headers: {
                                Accept: "application/json",
                                "Content-Type": "application/json",
                                "CSRF-Token": getCookie("XSRF-TOKEN"),
                            },
                            body: JSON.stringify({ idToken }),
                        }).then(() => {
                            
                        })
                    });
                    ic.classList.remove("fa");
                    ic.classList.remove("fa-spinner");
                    ic.classList.remove("fa-spin");
            })
            .then(() => {
                window.location = "http://localhost:8080";
            })
            .catch((error) => {
                mess.textContent = error;
                win.classList.add('fadeIn');
                win.style.display = "block";
            });
        }
    }
}

function getCookie(cname) {
    var name = cname + "=";
    var decodedCookie = decodeURIComponent(document.cookie);
    var ca = decodedCookie.split(';');
    for (var i = 0; i < ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) == ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}

function hideOK() {

    var win = document.getElementById("note");
    var mail = document.getElementById("email").value;
    //btn = document.getElementById("note");

    win.style.display = "none";
    var mess = document.getElementById("msg");
    win.style.visibility = "hidden";

    var ic = document.getElementById("ic");
    ic.classList.remove("fa");
    ic.classList.remove("fa-spinner");
    ic.classList.remove("fa-spin");

    if (mess.textContent == "Your account was successfully created \n " + "An email with a verification link was sent to " + mail) {
        var user = firebase.auth().currentUser;
        user.sendEmailVerification().then(function () {

            win.style.display = "block";

            ///mess.textContent = ";

            document.getElementById("ok").addEventListener("click", function (event) {

                window.location = "https://synblend.com";
            });
        }).catch(function (error) {
            mess.textContent = error;
        });
    }
}

function sc() {

    var win = document.getElementById("social");
    //win.classList.remove("fadeOut");
    win.classList.add('fadeIn');
    win.style.display = "block";
    win.style.visibility = "visible";
}

function cs() {

    var win = document.getElementById("social");
    win.classList.remove("fadeIn");
    win.style.display = "none";
    win.style.visibility = "hidden";
}

function cp() {
    var win = document.getElementById("PersonalInfoPanel");
    var nav = document.getElementById("nav");
    //Show panel
    if (win.style.display == "none") {
        nav.classList.remove('fadeOut')
        nav.classList.add('fadeOut')
        win.classList.remove('fadeOut');
        win.classList.add("fadeIn");
        win.style.display = "block";
        win.style.visibility = "visible";
    }
    else { //hide panel
        win.classList.remove('fadeIn');
        nav.classList.remove('fadeOut');
        nav.classList.add('fadeIn')
        win.classList.add("fadeOut");
        win.style.display = "none";
        win.style.visibility = "hidden";
    }
}

function csec() {
    var win = document.getElementById("SecurityPanel");
    var nav = document.getElementById("nav");
    //Show panel
    if (win.style.display == "none") {
        nav.classList.remove('fadeOut')
        nav.classList.add('fadeOut')
        win.classList.remove('fadeOut');
        win.classList.add("fadeIn");
        win.style.display = "block";
        win.style.visibility = "visible";
    }
    else { //hide panel
        win.classList.remove('fadeIn');
        nav.classList.remove('fadeOut');
        nav.classList.add('fadeIn')
        win.classList.add("fadeOut");
        win.style.display = "none";
        win.style.visibility = "hidden";
    }
}

function cacc() {
    var win = document.getElementById("AccountPanel");
    var nav = document.getElementById("nav");
    //Show panel
    if (win.style.display == "none") {
        nav.classList.remove('fadeOut')
        nav.classList.add('fadeOut')
        win.classList.remove('fadeOut');
        win.classList.add("fadeIn");
        win.style.display = "block";
        win.style.visibility = "visible";
    }
    else { //hide panel
        win.classList.remove('fadeIn');
        nav.classList.remove('fadeOut');
        nav.classList.add('fadeIn')
        win.classList.add("fadeOut");
        win.style.display = "none";
        win.style.visibility = "hidden";
    }
}

function fb() {
    var provider = new firebase.auth.FacebookAuthProvider();
    firebase.auth().signInWithPopup(provider).then(function (result) {
        // This gives you a Facebook Access Token. You can use it to access the Facebook API.
        //var token = result.credential.accessToken;

        var user = result.user;
        return user.getIdToken().then((idToken) => {
            return fetch("/loginsession", {
                method: "POST",
                headers: {
                    Accept: "application/json",
                    "Content-Type": "application/json",
                    "CSRF-Token": getCookie("XSRF-TOKEN"),
                },
                body: JSON.stringify({ idToken }),
            }).then(() => {

            })
        });
        ic.classList.remove("fa");
        ic.classList.remove("fa-spinner");
        ic.classList.remove("fa-spin");
    })
        .then(() => {
            //Redirect user to requested location
            window.location = "http://localhost:8080";
        })
        .catch((error) => {
            mess.textContent = error;
            win.classList.add('fadeIn');
            win.style.display = "block";
        });
}

function gs() {
    var win = document.getElementById("note");
    var mess = document.getElementById("msg");

    var provider = new firebase.auth.GoogleAuthProvider();
    firebase.auth().signInWithPopup(provider).then(function(result) {
         // This gives you a Google Access Token. You can use it to access the Google API.
        var token = result.credential.accessToken;
        // The signed-in user info.
        //Test Begin
        var user = firebase.auth().currentUser;
        //var name, email, photoUrl, uid, emailVerified;
        return user.getIdToken().then((idToken) => {
            return fetch("/loginsession", {
                method: "POST",
                headers: {
                    Accept: "application/json",
                    "Content-Type": "application/json",
                    "CSRF-Token": getCookie("XSRF-TOKEN"),
                },
                body: JSON.stringify({ idToken }),
            }).then(() => {

            })
        });
        ic.classList.remove("fa");
        ic.classList.remove("fa-spinner");
        ic.classList.remove("fa-spin");
    })
        .then(() => {
            //Redirect user to requested location
            window.location = "http://localhost:8080";
        })
        .catch((error) => {
            mess.textContent = error;
            win.classList.add('fadeIn');
            win.style.display = "block";
        });
}

function signOut() {
    firebase.auth().onAuthStateChanged(user => {
        if (user) {
            firebase.auth().signOut()
                .then(() => {
                    var a = document.getElementById('out');
                    a.style.display = 'block';
                    a.style.visibility = 'visible';
                    a.classList.add('fadeIn');

                    fetch('/logout').then(() => {
                        window.location = "/login"
                    })
                })
                .catch(e => {
                    var errorMessage = e;
                    var win = document.getElementById("note");
                    var mess = document.getElementById("msg");
                    mess.textContent = errorMessage;
                    win.classList.add('fadeIn');
                    win.style.display = "block";
                });
        }
    })

}

function checkAuth() {
    firebase.auth().onAuthStateChanged(user => {
        if (user) {
            alert('In')
            
            if (user.displayName.indexOf(' ') >= 0) {
                var name = user.displayName.substring(0, user.displayName.indexOf(' '));
                document.getElementById('wel').textContent = "Welcome, " + name;
            }
            else {
                document.getElementById('wel').textContent = "Welcome, " + user.displayName;
            }
        } else {
            alert('Out');
        }
    })
}

function createRedURL() {
    sessionStorage.setItem("redirect", document.URL);
}

function getRedURL() {
    return sessionStorage.getItem("redirect");
}