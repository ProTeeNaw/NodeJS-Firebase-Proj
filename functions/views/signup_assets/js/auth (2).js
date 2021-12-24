//document.body.style.zoom = "90%";

const Http = new XMLHttpRequest();
const url = 'http://localhost:8080/login';
Http.open("GET", url);
Http.send("Tino");

Http.onreadystatechange = (e) => {
    console.log(Http.responseText)
}

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
                        document.getElementById("ok").addEventListener("click", function (event) {
                           
                           // window.location = "https://synblend.com";
                        });
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

//============================================================================
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
            firebase.auth().signInWithEmailAndPassword(userEmail, userPass).then(function () {
                //Successful login
                firebase.auth().onAuthStateChanged(function (user) {
                    if (user) {
                        //User is logged in
                        user.getIdToken().then(function (idToken) {
                            var now = new Date();
                            now.setTime(now.getTime() + 1 * 3600 * 1000);
                            //document.cookie = "_ftlgsnb=" + idToken + "; expires = " + now.toUTCString() + "; path = /";
                            //Remove loader icon
                            ic.classList.remove("fa");
                            ic.classList.remove("fa-spinner");
                            ic.classList.remove("fa-spin");
                            //Redirect to home page
                            alert(user.displayName)
                            //Start test
                            
                            //});
                            //End test
                            //window.location.href = "https://synblend.com"
                        }).catch((error) => {
                            mess.textContent = "An error occured";
                            win.classList.add('fadeIn');
                            win.style.display = "block";
                        });
                    } else {
                        //User is not logged in
                    }
                });
            }).catch(function (error) {
                mess.textContent = error;
                win.classList.add('fadeIn');
                win.style.display = "block";
                //win.display.visibility = "visible";
                btn.disabled = false;
                check = false;
            })
        }
    }
}

//============================================================================

//async function login() {
//    alert('Starting now...')
//    firebase.auth().onAuthStateChanged(function (user) {
//        if (user) {
//            alert('1');
//            user.getIdToken().then(function (idToken) {  // <------ Check this line
//                console.log(idToken); // It shows the Firebase token now
//                var now = new Date();
//                now.setTime(now.getTime() + 1 * 3600 * 1000);
//                document.cookie = "token=" + idToken +"; expires = " + now.toUTCString() + "; path = /";
//            }).catch((error) => {
//                this.response = "Error getting auth token"
//                //});
//            });           
//        } else {
//            alert('0');
//        }
//    });
//}

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
        var token = result.credential.accessToken;
        // The signed-in user info.
        var user = result.user;
        // ...
    }).catch(function (error) {
        // Handle Errors here.
        var errorCode = error.code;
        var errorMessage = error.message;
        // The email of the user's account used.
        var email = error.email;
        // The firebase.auth.AuthCredential type that was used.
        var credential = error.credential;
        // ...
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
        var name, email, photoUrl, uid, emailVerified;

        if (user != null) {
            name = user.displayName;
            user.getIdToken().then(function (idToken) {
                var now = new Date();
                now.setTime(now.getTime() + 1 * 3600 * 1000);
                //document.cookie = "_ftlgsnb=" + idToken + "; expires = " + now.toUTCString() + "; path = /";
                //make http req
                
                //Remove loader icon
                ic.classList.remove("fa");
                ic.classList.remove("fa-spinner");
                ic.classList.remove("fa-spin");
                //Redirect to home page
                alert(user.displayName)
                window.location.href = "https://synblend.com"
            }).catch((error) => {
                mess.textContent = "An error occured";
                win.classList.add('fadeIn');
                win.style.display = "block";
            });
        }
        //Test end
  // ...
    }).catch(function (error) {

        var errorMessage = error.message;
        var win = document.getElementById("note");
        var mess = document.getElementById("msg");
        mess.textContent = errorMessage;
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
                    document.cookie = "_ftlgsnb=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
                    window.location.href = "https://synblend.com"
                })
                .catch(e => {
                    var errorMessage = "An error occured while signing out"
                    var win = document.getElementById("note");
                    var mess = document.getElementById("msg");
                    mess.textContent = errorMessage;
                    win.classList.add('fadeIn');
                    win.style.display = "block";
                });
            alert('put url here')
        }
    })

}

//document.getElementById('logout').addEventListener('click', function () {  
//    firebase.auth().onAuthStateChanged(user => {
//        if (user) {
//            firebase.auth().signOut()
//                .then(() => {
//                    var a = document.getElementById('out');
//                    a.style.display = 'block';
//                    a.style.visibility = 'visible';
//                    a.classList.add('fadeIn');
//                    document.cookie = "_ftlgsnb=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
//                    window.location.href = "https://synblend.com"
//                })
//                .catch(e => {
//                    var errorMessage = "An error occured while signing out"
//                    var win = document.getElementById("note");
//                    var mess = document.getElementById("msg");
//                    mess.textContent = errorMessage;
//                    win.classList.add('fadeIn');
//                    win.style.display = "block";
//                });
//        }
//    })
//});

window.addEventListener("load", checkAuth);

function checkAuth() {
    firebase.auth().onAuthStateChanged(user => {
        if (user) {
            var name = user.displayName.substring(0, user.displayName.indexOf(' '));
            document.getElementById('wel').textContent = "Welcome, " + name;
        }
        else {
            location = 'localhost:8080'
        }
    })
}