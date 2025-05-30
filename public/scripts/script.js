document.addEventListener("DOMContentLoaded", () => {
  const loader = document.getElementById("loader");
  const homepageContent = document.getElementById("homepage-content");

  const lastVisit = localStorage.getItem("lastVisit");
  const currentTime = new Date().getTime();

  // If there's a last visit timestamp, check if an hour has passed
  if (lastVisit && currentTime - lastVisit < 3600000) { // 1 hour = 3600000ms
    // If the page was visited within the last hour, skip the loader
    loader.classList.add("hidden");
    homepageContent.style.display = "block";
    initializeAnimations();
  } else {
    // If it's the first visit or an hour has passed, show the loader
    localStorage.setItem("lastVisit", currentTime); // Update the visit timestamp

    let mm = gsap.matchMedia();

    mm.add("(min-width: 768px)", () => {
      gsap.to(".moon", { scale: 3, opacity: 1, duration: 2, ease: "power2.inOut" });
      gsap.to(".sword-left", { x: 850, rotate: 180, duration: 2, scaleX: -1, ease: "power2.inOut" });
      gsap.to(".sword-right", { x: -850, rotate: -180, duration: 2, ease: "power2.inOut", onComplete: () => {
        loader.classList.add("hidden");
        homepageContent.style.display = "block";
        initializeAnimations();
      } });
    });

    mm.add("(max-width: 767px)", () => {
      gsap.to(".moon", { scale: 1.3, opacity: 1, duration: 2, ease: "power2.inOut" });
      gsap.to(".sword-left", { x: 250, rotate: 180, duration: 2, scaleX: -1, ease: "power2.inOut" });
      gsap.to(".sword-right", { x: -250, rotate: -180, duration: 2, ease: "power2.inOut", onComplete: () => {
        loader.classList.add("hidden");
        homepageContent.style.display = "block";
        initializeAnimations();
      } });
    });
  }

  // Handle audio unmute after user interaction
  const audio = document.getElementById("background-sound");
  document.addEventListener("click", () => {
    audio.muted = false;
  });
});

// Your custom animation function
function initializeAnimations() {
  // Add any animations you want to run after the loader
  console.log("Animations initialized!");
}

const AsHamburger = document.querySelector('.As-hamburger');
const AsNavLinks = document.querySelector('.As-nav-links');

AsHamburger.addEventListener('click', () => {
  AsNavLinks.classList.toggle('active');
});
// Function to initialize other animations
function initializeAnimations() {
  // GSAP code for T-shirt animation
  let mm = gsap.matchMedia();

  mm.add("(min-width: 1024px)", () => {
    var tl = gsap.timeline({
      scrollTrigger: {
        trigger: "#page2",
        start: "0% 95%",
        end: "50% 50%",
        scrub: true,
      },
    });

    tl.to("#move_image", {
      top: "145%",
      left: "28%",
      width: "19rem",
      duration: 1,
    });
  });

  mm.add("(max-width: 1024px) and (min-width: 768px)", () => {
    var tl = gsap.timeline({
      scrollTrigger: {
        trigger: "#page2",
        start: "0% 40%",
        end: "10% 40%",
        scrub: true,
      },
    });

    tl.to("#move_image", {
      top: "76%",
      left: "55%",
      height: "18rem",
      duration: 1,
    });
  });

  mm.add("(max-width: 600px)", () => {
    var tl = gsap.timeline({
      scrollTrigger: {
        trigger: "#page2",
        start: "0% 5%",
        end: "40% 40%",
        scrub: true,
      },
    });

    tl.to("#move_image", {
      top: "105%",
      left: "18%",
      height: "14rem",
      duration: 1,
    });
  });

  // Script for horizontal scrolling
  gsap.registerPlugin(ScrollTrigger);

  const scroller = document.querySelector(".scroller");

  gsap.to(scroller, {
    x: () => -(scroller.scrollWidth - document.documentElement.clientWidth) + "px",
    ease: "none",
    scrollTrigger: {
      trigger: ".page4",
      start: "top top",
      end: () => "+=" + (scroller.scrollWidth - document.documentElement.clientWidth),
      scrub: true,
      pin: true,
    },
  });

  // Script for notification text
  gsap.to(".notification-text", {
    x: "-100%",
    duration: 15,
    repeat: -1,
    ease: "linear",
  });
}






const swiper = new Swiper('.mySwiper', {
  effect: "coverflow",
  grabCursor: true,
  centeredSlides: true,
  slidesPerView: "auto", // Important for different sizes
  loop: true,
  autoplay: {
    delay: 4000,
    disableOnInteraction: false,
  },
  coverflowEffect: {
    rotate: 0,
    stretch: 0,
    depth: 100,
    modifier: 2.5,
    slideShadows: false,
  },
  pagination: {
    el: ".swiper-pagination",
    clickable: true,
  },
});


