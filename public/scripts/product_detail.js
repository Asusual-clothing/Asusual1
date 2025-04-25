  const productId = "your-product-id-here"; // This should be the actual product ID

  async function fetchProductDetails() {
    try {
      const response = await fetch(`http://localhost:5000/api/product/${productId}`);
      const product = await response.json();

      // Update the product details dynamically
      document.querySelector('h2').innerText = product.name;
      document.querySelector('.price').innerText = `₹${product.price}`;
      document.querySelector('.info-section p').innerText = product.description;

      const imageGallery = document.querySelector('.image-scroll');
      product.images.forEach(image => {
        const imgElement = document.createElement('img');
        imgElement.src = image;
        imgElement.alt = product.name;
        imageGallery.appendChild(imgElement);
      });

      // Update size options
      const sizeOptions = document.querySelector('.size-options');
      product.sizes.forEach(size => {
        const sizeButton = document.createElement('button');
        sizeButton.innerText = size;
        sizeOptions.appendChild(sizeButton);
      });

      // Update color options
      const colorOptions = document.querySelector('.color-options');
      product.colors.forEach(color => {
        const colorBox = document.createElement('span');
        colorBox.classList.add('color-box', color.toLowerCase());
        colorOptions.appendChild(colorBox);
      });
    } catch (error) {
      console.error("Error fetching product details:", error);
    }
  }

  // Fetch product details on page load
  fetchProductDetails();

