document.addEventListener("DOMContentLoaded", function() {
    // Initialize cart on page load
    updateCart();

    // Function to update cart totals
    function updateCart() {
        let totalItems = 0;
        let subtotal = 0;
        const shipping = cartData.deliveryCost ;
        
        document.querySelectorAll(".cart-item").forEach(item => {
        const quantityElem = item.querySelector(".cart-quantity");
        const quantity = parseInt(quantityElem.textContent);
        const price = parseFloat(item.dataset.price);
        const itemTotalElem = item.querySelector(".item-total");

        const itemTotal = price * quantity;
        itemTotalElem.textContent = itemTotal.toFixed(2);
        totalItems += quantity;
        subtotal += itemTotal;
    });

        // Calculate discount if coupon is applied
        let discountAmount = 0;
        const couponElement = document.querySelector('.coupon-success');
        if (couponElement) {
            const couponText = couponElement.textContent;
            if (couponText.includes('%')) {
                const discountPercent = parseFloat(couponText.match(/(\d+)%/)[1]);
                discountAmount = subtotal * (discountPercent / 100);
            } else {
                const fixedDiscount = parseFloat(couponText.match(/Rs(\d+)/)[1]);
                discountAmount = Math.min(fixedDiscount, subtotal);
            }
        }

        // Update DOM elements
        document.getElementById("total-items").textContent = totalItems;
        document.getElementById("total-price").textContent = subtotal.toFixed(2);
        
        const discountedSubtotal = subtotal - discountAmount;
        const finalTotal = Math.max(0, discountedSubtotal + shipping);
        
        document.querySelector(".total-line span:last-child").textContent = `Rs ${finalTotal.toFixed(2)}`;
        
        const discountMessage = document.querySelector('.discount-message');
        if (discountAmount > 0) {
            if (!discountMessage) {
                const messageElement = document.createElement('p');
                messageElement.className = 'discount-message';
                messageElement.textContent = `You saved: Rs ${discountAmount.toFixed(2)}`;
                document.querySelector('.summary-total').insertBefore(messageElement, document.querySelector('.order_btn_animation'));
            } else {
                discountMessage.textContent = `You saved: Rs ${discountAmount.toFixed(2)}`;
            }
        } else if (discountMessage) {
            discountMessage.remove();
        }
    }

    // Proceed to order button
    document.getElementById('proceed-to-order')?.addEventListener('click', function() {
        this.style.display = 'none';
        document.getElementById('shipping-form-container').style.display = 'block';
    });

    // Cancel order button
    document.getElementById('cancel-order')?.addEventListener('click', function() {
        document.getElementById('proceed-to-order').style.display = 'block';
        document.getElementById('shipping-form-container').style.display = 'none';
    });

    // Form submission
    document.getElementById('shipping-form')?.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const button = document.querySelector('.order');
        button.classList.add("active");
        
        try {
            const shippingAddress = {
                line1: document.getElementById('shipping-line1').value,
                line2: document.getElementById('shipping-line2').value,
                city: document.getElementById('shipping-city').value,
                state: document.getElementById('shipping-state').value,
                postalCode: document.getElementById('shipping-postalCode').value,
                country: document.getElementById('shipping-country').value,
                contactNumber: document.getElementById('shipping-contactNumber').value
            };

            // Basic validation
            if (!shippingAddress.line1 || !shippingAddress.city || 
                !shippingAddress.state || !shippingAddress.postalCode || 
                !shippingAddress.country || !shippingAddress.contactNumber) {
                alert('Please fill in all required fields');
                button.classList.remove("active");
                return;
            }

            const response = await fetch('/place-order', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ 
                    shippingAddress,
                    paymentMethod: 'COD'
                })
            });

            const data = await response.json();

            if (data.success) {
                setTimeout(() => {
                    window.location.href = `/confirmation/${data.orderId}`;
                }, 2000);
            } else {
                alert('Failed to create order: ' + data.message);
                button.classList.remove("active");
            }
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred while placing your order');
            button.classList.remove("active");
        }
    });

    // Quantity increase handlers
    document.querySelectorAll(".increase").forEach(button => {
        button.addEventListener("click", function() {
            const quantityElem = this.parentElement.querySelector('.cart-quantity');
            const newQuantity = parseInt(quantityElem.textContent) + 1;
            quantityElem.textContent = newQuantity;
            updateCart();
            updateQuantityInDatabase(quantityElem, newQuantity);
        });
    });

    // Quantity decrease handlers
    document.querySelectorAll(".decrease").forEach(button => {
        button.addEventListener("click", function() {
            const quantityElem = this.parentElement.querySelector('.cart-quantity');
            const currentQuantity = parseInt(quantityElem.textContent);

            if (currentQuantity > 1) {
                const newQuantity = currentQuantity - 1;
                quantityElem.textContent = newQuantity;
                updateCart();
                updateQuantityInDatabase(quantityElem, newQuantity);
            }
        });
    });

    // Remove item handlers
    document.querySelectorAll(".cart-remove").forEach(button => {
        button.addEventListener("click", function() {
            const cartItem = this.closest('.cart-item');
            cartItem.remove();
            updateCart();
            removeItemFromDatabase(this);
        });
    });

    // Helper functions for cart operations
    async function updateQuantityInDatabase(item, newQuantity) {
        const cartItem = item.closest('.cart-item');
        const productId = cartItem.dataset.productId;
        const size = cartItem.querySelector('.cart-item-size').textContent.replace('Size: ', '').trim();
        
        try {
            const response = await fetch('/cart/update-quantity', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    productId,
                    size,
                    quantity: newQuantity
                })
            });
            
            const data = await response.json();
            if (!data.success) {
                console.error('Error updating quantity:', data.message);
                item.textContent = parseInt(item.textContent) - (newQuantity > parseInt(item.textContent) ? -1 : 1);
                updateCart();
            }
        } catch (error) {
            console.error('Error updating quantity:', error);
            item.textContent = parseInt(item.textContent) - (newQuantity > parseInt(item.textContent) ? -1 : 1);
            updateCart();
        }
    }

    async function removeItemFromDatabase(item) {
        const cartItem = item.closest('.cart-item');
        const productId = cartItem.dataset.productId;
        const size = cartItem.querySelector('.cart-item-size').textContent.replace('Size: ', '').trim();
        
        try {
            const response = await fetch('/cart/remove-item', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    productId,
                    size
                })
            });
            
            const data = await response.json();
            if (!data.success) {
                console.error('Error removing item:', data.message);
                document.querySelector('.cart-items-section').insertBefore(cartItem, document.querySelector('.cart-back'));
                updateCart();
            }
        } catch (error) {
            console.error('Error removing item:', error);
            document.querySelector('.cart-items-section').insertBefore(cartItem, document.querySelector('.cart-back'));
            updateCart();
        }
    }

    // Animation for order button
    document.querySelector('.order')?.addEventListener('click', function(e) {
        let button = $(this);
        if(!button.hasClass('animate')) {
            button.addClass('animate');
            setTimeout(() => {
                button.removeClass('animate');
            }, 10000);
        }
    });
});