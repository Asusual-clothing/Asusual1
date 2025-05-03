const container = document.getElementById("container");
const signUpButton = document.getElementById("signUpOverlay");
const signInButton = document.getElementById("signInOverlay");


signUpButton.addEventListener("click", () => {
    container.classList.add("right-panel-active");
});

signInButton.addEventListener("click", () => {
    container.classList.remove("right-panel-active");
});

// Add this to your existing script
document.getElementById('signInOverlay').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('container').classList.remove('right-panel-active');
  });
  
  document.getElementById('signUpOverlay').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('container').classList.add('right-panel-active');
  });