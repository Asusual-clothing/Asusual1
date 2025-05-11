/*
  Lerp function for smooth animations
  https://codepen.io/rachsmith/post/animation-tip-lerp
*/
function lerp({ x, y }, { x: targetX, y: targetY }) {
    const fraction = 0.1;
    
    x += (targetX - x) * fraction;
    y += (targetY - y) * fraction;
    
    return { x, y };
}

class Slider {
    constructor(el) {
        const imgClass = this.IMG_CLASS = 'slider__images-item';
        const textClass = this.TEXT_CLASS = 'slider__text-item';
        const activeImgClass = this.ACTIVE_IMG_CLASS = `${imgClass}--active`;
        const activeTextClass = this.ACTIVE_TEXT_CLASS = `${textClass}--active`;
        
        this.el = el;
        this.contentEl = document.getElementById('slider-content');
        this.onMouseMove = this.onMouseMove.bind(this);
        
        // Elements
        this.activeImg = el.getElementsByClassName(activeImgClass);
        this.activeText = el.getElementsByClassName(activeTextClass);
        this.images = el.getElementsByTagName('img');
        
        // Event listeners for desktop
        document.getElementById('left').addEventListener('click', this.prev.bind(this));
        document.getElementById('right').addEventListener('click', this.next.bind(this));
        
        // Event listeners for dots (both desktop and mobile)
        document.querySelectorAll('#slider-dots, #slider-dots-mobile').forEach(container => {
            container.addEventListener('click', this.onDotClick.bind(this));
            container.addEventListener('touchend', this.onDotClick.bind(this));
        });
        
        // Touch events for mobile swipe
        this.touchStartX = 0;
        this.touchEndX = 0;
        this.swipeThreshold = 50;
        el.addEventListener('touchstart', this.handleTouchStart.bind(this), { passive: true });
        el.addEventListener('touchend', this.handleTouchEnd.bind(this), { passive: false });
        
        // Resize handling
        window.addEventListener('resize', this.onResize.bind(this));
        
        this.onResize();
        this.length = this.images.length;
        this.lastX = this.lastY = this.targetX = this.targetY = 0;
        this.createDotIndicator();
      }

    onResize() {
        const htmlStyles = getComputedStyle(document.documentElement);
        const mobileBreakpoint = htmlStyles.getPropertyValue('--mobile-bkp');
        
        const isMobile = this.isMobile = matchMedia(
            `only screen and (max-width: ${mobileBreakpoint})`
        ).matches;
        
        this.halfWidth = innerWidth / 2;
        this.halfHeight = innerHeight / 2;
        this.zDistance = htmlStyles.getPropertyValue('--z-distance');
        
        if (!isMobile && !this.mouseWatched) {
            this.mouseWatched = true;
            this.el.addEventListener('mousemove', this.onMouseMove);
            this.el.style.setProperty(
                '--img-prev', 
                `url(${this.images[+this.activeImg[0].dataset.id - 1].src})`
            );
            this.contentEl.style.setProperty('transform', `translateZ(${this.zDistance})`);
        } else if (isMobile && this.mouseWatched) {
            this.mouseWatched = false;
            this.el.removeEventListener('mousemove', this.onMouseMove);
            this.contentEl.style.setProperty('transform', 'none');
        }
    }

    getMouseCoefficients({ pageX, pageY } = {}) {
        const halfWidth = this.halfWidth;
        const halfHeight = this.halfHeight;
        const xCoeff = ((pageX || this.targetX) - halfWidth) / halfWidth;
        const yCoeff = (halfHeight - (pageY || this.targetY)) / halfHeight;
        
        return { xCoeff, yCoeff };
    }

    onMouseMove({ pageX, pageY }) {   
        this.targetX = pageX;
        this.targetY = pageY;
        
        if (!this.animationRunning) {
            this.animationRunning = true;
            this.runAnimation();
        }
    }

    runAnimation() {
        if (this.animationStopped) {
            this.animationRunning = false;
            return;
        }
        
        const maxX = 10;
        const maxY = 10;
        
        const newPos = lerp({
            x: this.lastX,
            y: this.lastY
        }, {
            x: this.targetX,
            y: this.targetY
        });
        
        const { xCoeff, yCoeff } = this.getMouseCoefficients({
            pageX: newPos.x, 
            pageY: newPos.y
        });
            
        this.lastX = newPos.x;
        this.lastY = newPos.y;

        this.positionImage({ xCoeff, yCoeff });
        
        this.contentEl.style.setProperty('transform', `
            translateZ(${this.zDistance})
            rotateX(${maxY * yCoeff}deg)
            rotateY(${maxX * xCoeff}deg)
        `);
        
        if (this.reachedFinalPoint) {
            this.animationRunning = false;
        } else {
            requestAnimationFrame(this.runAnimation.bind(this)); 
        }
    }

    get reachedFinalPoint() {
        const lastX = ~~this.lastX;
        const lastY = ~~this.lastY;
        const targetX = this.targetX;
        const targetY = this.targetY;
        
        return (lastX == targetX || lastX - 1 == targetX || lastX + 1 == targetX) 
            && (lastY == targetY || lastY - 1 == targetY || lastY + 1 == targetY);
    }

    positionImage({ xCoeff, yCoeff }) {
        const maxImgOffset = 1;
        const currentImage = this.activeImg[0].children[0];
        
        currentImage.style.setProperty('transform', `
            translateX(${maxImgOffset * -xCoeff}em)
            translateY(${maxImgOffset * yCoeff}em)
        `);  
    }

    onDotClick(event) {
        // Prevent default for touch events
        if (event.type === 'touchend') {
            event.preventDefault();
        }
        
        if (this.inTransit) return;
        
        // Handle both regular and mobile dots
        const dot = event.target.closest('.slider__nav-dot') || 
                    event.target.closest('.slider__nav-dot--mobile');
        
        if (!dot) return;
        
        const nextId = dot.dataset.id;
        const currentId = this.activeImg[0].dataset.id;
        
        if (currentId == nextId) return;
        
        this.startTransition(nextId);
    }

    updateActiveDot(activeId) {
        // Update both desktop and mobile dots
        document.querySelectorAll('.slider__nav-dot, .slider__nav-dot--mobile').forEach(dot => {
            dot.classList.remove('slider__nav-dot--active');
            if (dot.getAttribute('data-id') === activeId) {
                dot.classList.add('slider__nav-dot--active');
            }
        });
    }
    updateDotIndicator(activeId) {
  const activeDot = document.querySelector(`.slider__nav-dot[data-id="${activeId}"]`);
  if (!activeDot) return;
  
  const dotsContainer = document.querySelector('.slider__nav-dots');
  const indicator = document.querySelector('.slider__nav-dots-indicator');
  
  if (!indicator) {
    // Create indicator if it doesn't exist
    const newIndicator = document.createElement('div');
    newIndicator.className = 'slider__nav-dots-indicator';
    dotsContainer.appendChild(newIndicator);
    return this.updateDotIndicator(activeId); // Try again
  }
  
  const dotRect = activeDot.getBoundingClientRect();
  const containerRect = dotsContainer.getBoundingClientRect();
  
  const position = dotRect.left - containerRect.left + (dotRect.width / 2) - 12;
  indicator.style.transform = `translateX(${position}px)`;
}
createDotIndicator() {
    const dotsContainer = document.querySelector('.slider__nav-dots--mobile');
    if (dotsContainer && !dotsContainer.querySelector('.slider__nav-dot-indicator')) {
      const indicator = document.createElement('div');
      indicator.className = 'slider__nav-dot-indicator';
      dotsContainer.appendChild(indicator);
      
      // Position indicator for initial active dot
      this.updateDotIndicator(this.activeImg[0].dataset.id);
    }
  }

  updateDotIndicator(activeId) {
    const activeDot = document.querySelector(`.slider__nav-dots--mobile .slider__nav-dot[data-id="${activeId}"]`);
    const indicator = document.querySelector('.slider__nav-dot-indicator');
    
    if (activeDot && indicator) {
      const dotRect = activeDot.getBoundingClientRect();
      const containerRect = activeDot.parentElement.getBoundingClientRect();
      const position = dotRect.left - containerRect.left + (dotRect.width / 2) - 12;
      
      indicator.style.transform = `translateX(${position}px)`;
    }
  }

    transitionItem(nextId) {
        function onImageTransitionEnd(e) {
            e.stopPropagation();
            
            nextImg.classList.remove(transitClass);
            
            self.inTransit = false;
            
            this.className = imgClass;
            this.removeEventListener('transitionend', onImageTransitionEnd);
        }
        
        const self = this;
        const el = this.el;
        const currentImg = this.activeImg[0];
        const currentId = currentImg.dataset.id;
        const imgClass = this.IMG_CLASS;
        const textClass = this.TEXT_CLASS;
        const activeImgClass = this.ACTIVE_IMG_CLASS;
        const activeTextClass = this.ACTIVE_TEXT_CLASS;
        const subActiveClass = `${imgClass}--subactive`;
        const transitClass = `${imgClass}--transit`;
        const nextImg = el.querySelector(`.${imgClass}[data-id='${nextId}']`);
        const nextText = el.querySelector(`.${textClass}[data-id='${nextId}']`);
        
        let outClass = '';
        let inClass = '';

        this.animationStopped = true;
        
        nextText.classList.add(activeTextClass);
        
        el.style.setProperty('--from-left', nextId);
        
        currentImg.classList.remove(activeImgClass);
        currentImg.classList.add(subActiveClass);
        
        if (currentId < nextId) {
            outClass = `${imgClass}--next`;
            inClass = `${imgClass}--prev`;
        } else {
            outClass = `${imgClass}--prev`;
            inClass = `${imgClass}--next`;
        }
        
        nextImg.classList.add(outClass);
        
        requestAnimationFrame(() => {
            nextImg.classList.add(transitClass, activeImgClass);
            nextImg.classList.remove(outClass);
            
            this.animationStopped = false;
            this.positionImage(this.getMouseCoefficients());
            this.updateActiveDot(nextId);
            this.updateDotIndicator(nextId);
            
            currentImg.classList.add(transitClass, inClass);
            currentImg.addEventListener('transitionend', onImageTransitionEnd);
        });

        if (!this.isMobile) {
            this.switchBackgroundImage(nextId);
        }
    }

    startTransition(nextId) {
        function onTextTransitionEnd(e) {
            if (!e.pseudoElement) {
                e.stopPropagation();

                requestAnimationFrame(() => {
                    self.transitionItem(nextId);
                });

                this.removeEventListener('transitionend', onTextTransitionEnd);
            }
        }
        
        if (this.inTransit) return;

        const activeText = this.activeText[0];
        const backwardsClass = `${this.TEXT_CLASS}--backwards`;
        const self = this;
        
        this.inTransit = true;
        
        activeText.classList.add(backwardsClass);
        activeText.classList.remove(this.ACTIVE_TEXT_CLASS);
        activeText.addEventListener('transitionend', onTextTransitionEnd);
        
        requestAnimationFrame(() => {
            activeText.classList.remove(backwardsClass);
        });
    }

    next() {
        if (this.inTransit) return;
        
        let nextId = +this.activeImg[0].dataset.id + 1;
        
        if (nextId > this.length)
            nextId = 1;
        
        this.startTransition(nextId);
    }

    prev() {
        if (this.inTransit) return;
        
        let nextId = +this.activeImg[0].dataset.id - 1;
        
        if (nextId < 1)
            nextId = this.length;
        
        this.startTransition(nextId);
    }

    handleTouchStart(e) {
        if (!this.isMobile) return;
        this.touchStartX = e.changedTouches[0].screenX;
    }

    handleTouchEnd(e) {
        if (!this.isMobile) return;
        this.touchEndX = e.changedTouches[0].screenX;
        this.handleSwipe();
    }

    handleSwipe() {
        if (this.inTransit) return;
        
        const swipeDistance = this.touchEndX - this.touchStartX;
        
        if (Math.abs(swipeDistance) > this.swipeThreshold) {
            if (swipeDistance < 0) {
                this.next(); // Swipe left
            } else {
                this.prev(); // Swipe right
            }
        }
    }

    switchBackgroundImage(nextId) {
        function onBackgroundTransitionEnd(e) {
            if (e.target === this) {
                this.style.setProperty('--img-prev', imageUrl);
                this.classList.remove(bgClass);
                this.removeEventListener('transitionend', onBackgroundTransitionEnd);
            }
        }

        const bgClass = 'slider--bg-next';
        const el = this.el;
        const imageUrl = `url(${this.images[+nextId - 1].src})`;
        
        el.style.setProperty('--img-next', imageUrl);
        el.addEventListener('transitionend', onBackgroundTransitionEnd);
        el.classList.add(bgClass);
    }
}


// Initialize the slider when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    const sliderEl = document.getElementById('slider');
    if (sliderEl) {
        const slider = new Slider(sliderEl);

        // Auto-slide functionality
        let timer = 0;
        
        function autoSlide() {
            requestAnimationFrame(() => {
                slider.next();
            });
            
            timer = setTimeout(autoSlide, 5000);
        }
        
        function stopAutoSlide() {
            clearTimeout(timer);
            
            sliderEl.removeEventListener('touchstart', stopAutoSlide);
            sliderEl.removeEventListener('mousemove', stopAutoSlide);  
        }
        
        sliderEl.addEventListener('mousemove', stopAutoSlide);
        sliderEl.addEventListener('touchstart', stopAutoSlide);
        
        timer = setTimeout(autoSlide, 2000);
    } else {
        console.error('Slider element not found!');
    }
});