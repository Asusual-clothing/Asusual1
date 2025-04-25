const container = document.getElementById("container");
const signUpButton = document.getElementById("signUpOverlay");
const signInButton = document.getElementById("signInOverlay");


signUpButton.addEventListener("click", () => {
    container.classList.add("right-panel-active");
});

signInButton.addEventListener("click", () => {
    container.classList.remove("right-panel-active");
});
