
function hideLogin() {

    //remove animation classes
    document.getElementById("signUpPanel").classList.remove('zoomerOut');
    document.getElementById("loginPanel").classList.remove('zoomer');

    //add animation classes
    document.getElementById("loginPanel").classList.add('zoomerOut');
    setTimeout(showSignUpPanel, 1200);
    document.getElementById("signUpPanel").classList.add('zoomer');
}

function showSignUpPanel()
{
    document.getElementById("loginPanel").style.display = "none";
    document.getElementById("signUpPanel").style.display = "block";
    document.getElementById("title").textContent = "Sign Up | SynBlend";
    //document.getElementById("signUpPanel").classList.add('slideRight');
    
    //window.scrollTo(0, 0);
}

function hideSignUp()
{
    //remove animation classes
    document.getElementById("loginPanel").classList.remove('zoomerOut');
    document.getElementById("signUpPanel").classList.remove('zoomer');

    //add animation classes
    document.getElementById("signUpPanel").classList.add('zoomerOut');
    setTimeout(showLoginPanel, 1000);
    document.getElementById("loginPanel").classList.add('zoomer');
}

function showLoginPanel()
{
    document.getElementById("signUpPanel").style.display = "none";
    document.getElementById("loginPanel").style.display = "block";
    document.getElementById("title").textContent = "Login | SynBlend";
    //window.scrollTo(0, 0);
}