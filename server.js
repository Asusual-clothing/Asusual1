const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const randomstring = require('randomstring')
const cloudinary = require('cloudinary').v2;
const nodemailer = require('nodemailer');
const session = require('express-session');
const flash = require('connect-flash');
const dotenv = require('dotenv');
const crypto = require('crypto');
const MongoStore = require('connect-mongo');
const { uploads } = require('./config/cloudinary');
const methodOverride = require('method-override');

require('dotenv').config();     



// Initialize Express app
const app = express();
const PORT = process.env.PORT || 8000;

// Connect to MongoDB Atlas
mongoose.connect(process.env.MONGO_URI, {
    serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds instead of 10
    socketTimeoutMS: 45000,
})
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('MongoDB connection error:', err));




// Middleware to attach user to both req and views
const attachUser = async (req, res, next) => {
    try {
        const userId = req.session.userId || req.cookies.userId;
        req.user = userId ? await User.findById(userId, 'name email phone createdAt') : null;
        res.locals.user = req.user; // This makes user available in all views
        next();
    } catch (error) {
        console.error('User attachment error:', error);
        next(error);
    }
};

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());
app.use(methodOverride('_method'));
app.use(session({
    secret: process.env.SESSION_SECRET || 'Preaveen@8233',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    cookie: { secure: false, maxAge: 3600000 }
}));
app.use(express.json()); // For JSON bodies
app.use(express.urlencoded({ extended: true })); // For form data
app.use(flash());


// Make flash messages available to all views
app.use((req, res, next) => {
  res.locals.success = req.flash('success');
  res.locals.error = req.flash('error');
  next();
});
app.use(attachUser);
const otpCache = {};

function generateOTP() {
    return randomstring.generate({ length: 4, charset: 'numeric' })
}

function sendOTP(email, otp) {
    const mailOPTION = {
        from: 'asusualclothing@gmail.com',
        to: email,
        subject: 'OTP verification',
        text: `your otp is :${otp}`
    };


    let transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD

        },
        tls: {
            rejectUnauthorized: true
        }
    });

    transporter.sendMail(mailOPTION, (error, info) => {
        if (error) {
            console.log('error ', error);
        } else {
            console.log('OTP Email sent successfully:', info.response)
        }
    });
}



// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Import database models
const Product = require('./models/Product');
const User = require('./models/UserSchema');
const Cart = require('./models/CartSchema');
const Admin = require('./models/AdminSchema');
const CustomTshirt = require('./models/CustomTshirtSchema');
const Poster = require('./models/posterSchema');
const Order = require('./models/OrderSchema');
const Contact = require('./models/Contact')
const Coupon = require('./models/CouponSchema '); // Adjust path if needed


// Configure Multer for handling file uploads in memory


// Configure multer to use memory storage
const storage = multer.memoryStorage(); // Store files in memory as Buffer objects
const upload = multer({ storage: storage });
// Serve the signup page




//################################### admin login##########################################################
app.get('/admin-login', (req, res) => {
    res.render("admin_login");
})

app.get('/edit-poster', (req, res) => {
    res.render("edit_poster")
})

app.get('/admin-option', async (req, res) => {
    try {
        // Get counts in parallel
        const [totalProducts, totalOrders, activeCoupons] = await Promise.all([
            Product.countDocuments(),
            Order.countDocuments(),
            Coupon.countDocuments({ active: true })
        ]);

        res.render("admin_option", {
            counts: {
                totalProducts,
                totalOrders,
                activeCoupons
            },
            error: null // Explicitly set error to null when there's no error
        });
    } catch (error) {
        console.error('Error fetching counts:', error);
        // Render with default values if there's an error
        res.render("admin_option", {
            counts: {
                totalProducts: 0,
                totalOrders: 0,
                activeCoupons: 0
            },
            error: "Failed to load dashboard statistics" // Error message included
        });
    }
});

app.get('/Terms-and-conditions', (req, res) => {
    res.render("termsandcondition")
})

app.get('/Privacy-policy', (req, res) => {
    res.render("privacypolicy")
})



app.post('/admin/signup', async (req, res) => {
    try {
        const { name, email, password, confirmPassword } = req.body;

        if (password !== confirmPassword) {
            return res.status(400).send("Password and Confirm Password do not match");
        }

        // Hash the password before saving it to the database
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create a new user in the database
        const admin = await Admin.create({ name, email, password: hashedPassword });

        // console.log(admin);
        res.redirect('admin_login');

    } catch (error) {
        console.error('Error signing up user:', error);
        res.status(500).send('Error signing up user: ' + error.message);
    }
});




app.post('/admin/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const admin = await Admin.findOne({ email });

        if (!admin) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const isPasswordValid = await bcrypt.compare(password, admin.password);

        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Set session and cookie
        req.session.adminId = admin._id;
        res.cookie('adminId', admin._id, { httpOnly: true, secure: false, maxAge: 24 * 60 * 60 * 1000 });
        res.redirect("/admin-option");
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});




app.post('/admin/edit-poster', uploads.fields([
    { name: 'poster1', maxCount: 1 },
    { name: 'poster2', maxCount: 1 },
    { name: 'poster3', maxCount: 1 }
  ]), async (req, res) => {
    try {
      const files = req.files;
      const imageUrls = [];
      const headings = [];
      const titles = [];
  
      for (let i = 1; i <= 3; i++) {
        const field = `poster${i}`;
        if (files[field]) {
          const file = files[field][0];
  
          imageUrls.push(file.path); // Already a Cloudinary URL
          headings.push(req.body[`Heading${i}`] || '');
          titles.push(req.body[`Title${i}`] || '');
        }
      }
  
      const update = {
        image: imageUrls,
        Heading: headings,
        Title: titles
      };
  
      const poster = await Poster.findOneAndUpdate({}, update, {
        upsert: true,
        new: true,
        setDefaultsOnInsert: true
      });
      return res.send(`
        <script>
          alert('Poster updated successfully');
          window.location.href = '/';
        </script>
    `);
    } catch (error) {
      console.error('Cloudinary Upload Error:', error);

    }
  });


// Logout route
app.post('/admin/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ message: 'Failed to log out' });
        }
        res.clearCookie('adminId');
        res.redirect('/')
    });
});





app.get('/admindashboard', async (req, res) => {
    try {
        const products = await Product.find().sort({ createdAt: 'desc' });
        res.render('admindashboard', { products });
    } catch (error) {
        res.status(500).send('Error fetching products');
    }
})



//##################################### edit product ##################################################
// Update product by ID (edit_product route)
// Then your routes
app.post('/edit-product/:id',
    uploads.fields([
      { name: 'front_image', maxCount: 1 },
      { name: 'back_image', maxCount: 1 },
      { name: 'images', maxCount: 5 }
    ]),
    async (req, res) => {
      const { id } = req.params;
  
      try {
        const updateData = req.body;
  
        if (req.files['front_image']) {
          updateData.front_image = req.files['front_image'][0].path;
        }
        if (req.files['back_image']) {
          updateData.back_image = req.files['back_image'][0].path;
        }
        if (req.files['images']) {
          updateData.images = req.files['images'].map(img => img.path);
        }
  
        await Product.findByIdAndUpdate(id, updateData, { new: true });
  
        res.redirect('/Products');
      } catch (error) {
        console.error('Error updating product:', error);
        res.status(500).json({ success: false, error: error.message });
      }
    }
  );  



app.post('/delete_product/:id', async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id);
        res.redirect('/edit-product');
    } catch (err) {
        res.status(500).send("Error deleting product");
    }
});




app.get('/edit-product', async (req, res) => {
    const products = await Product.find({}, 'name price front_image category brand sizes description');
    const updatedProducts = products.map(product => ({
        ...product._doc,
        image: product.front_image.length > 0 ? product.front_image[0] : null
    }));
    res.render('edit_product', { products: updatedProducts });
});




//##################################### Handle homepage ####################################################
app.get('/', async (req, res) => {
    try {
        // Fetch products sorted by creation date
        const Products = await Product.find().sort({ createdAt: 'desc' });

        // Fetch the single document containing the poster images, headings, and titles
        const poster = await Poster.findOne({});
        const posters = poster ? poster.image : []; // Use an empty array if no posters are found
        const headings = poster ? poster.Heading : []; // Use an empty array if no headings are found
        const titles = poster ? poster.Title : []; // Use an empty array if no titles are found

        // Render the index.ejs template with Products, user, posters, headings, and titles
        res.render('index', { Products, posters, headings, titles });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});


app.get('/add-product', (req, res) => {
    res.render('add_product');
});


//ai based report analysis ,weekly analysis of police  criminal prediction

// Add to Cart Route
app.post('/add-to-cart', async (req, res) => {
    const { productId, quantity, size } = req.body;

    // Get user ID from session or cookie
    const userId = req.session.userId || req.cookies.userId;

    if (!userId) {
        return res.send(`
            <script>
              alert('Please log in to add item to cart');
              window.location.href = '/signup';
            </script>
        `);
    }

    try {
        // Find the user's cart
        let cart = await Cart.findOne({ user: userId });

        if (cart) {
            // Check if the item already exists in the cart
            const existingItem = cart.items.find(
                item => item.product.toString() === productId && item.size === size
            );

            if (existingItem) {
                // Update quantity if the item already exists
                existingItem.quantity += parseInt(quantity, 10);
            } else {
                // Add new item to the cart
                cart.items.push({ product: productId, quantity: parseInt(quantity, 10), size });
            }
            await cart.save();
            res.redirect('/cart')
        } else {
            // Create a new cart if it doesn't exist
            const newCart = new Cart({
                user: userId,
                items: [{ product: productId, quantity: parseInt(quantity, 10), size }]
            });

            await newCart.save();
            res.redirect('/cart')
        }
    } catch (error) {
        console.error('Error adding to cart:', error);
        res.status(500).json({ message: 'Internal server error', error });
    }
});


app.get('/product_details/:id', async (req, res) => {
    try {
        const productId = req.params.id;
        const product = await Product.findById(productId);

        if (!product) {
            return res.status(404).send('Product not found');
        }

        const userId = req.session.userId || req.cookies.userId;
        let user = { name: 'Guest' };

        if (userId) {
            user = await User.findById(userId, 'name _id');
        }

        // Explicitly passing productId as separate variable
        res.render('product_detail', {
            product,
            user,
            productId: product._id
        });

    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

app.get('/Products', async (req, res) => {
    try {
        const products = await Product.find().sort({ createdAt: 'desc' }).lean();
        res.render('allProduct', {
            products: products.map(p => ({
                ...p,
                id: p._id.toString() // Ensure id field exists
            }))
        });

    } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).send('Error fetching products');
    }
});

app.get('/coupons', async (req, res) => {
    try {
        const coupons = await Coupon.find().sort({ createdAt: -1 });
        res.render('coupon_form', {
            coupons,
            coupon: null
        });
    } catch (err) {
        console.error('Error fetching coupons:', err);
        res.redirect('/coupons');
    }
});

// GET: Form to add new coupon
app.get('/add-coupon', (req, res) => {
    res.render('coupon_form', {
        coupons: [],
        coupon: null
    });
});

// GET: Form to edit existing coupon
app.get('/edit/:id', async (req, res) => {
    try {
        const [coupons, coupon] = await Promise.all([
            Coupon.find().sort({ createdAt: -1 }),
            Coupon.findById(req.params.id)
        ]);

        if (!coupon) return res.redirect('/coupons');

        res.render('coupon_form', {
            coupons,
            coupon
        });
    } catch (err) {
        console.error('Error in edit route:', err);
        res.redirect('/coupons');
    }
});

// POST: Toggle coupon active status
app.post('/toggle-active/:id', async (req, res) => {
    try {
        const coupon = await Coupon.findById(req.params.id);
        if (!coupon) return res.redirect('/coupons');

        coupon.active = !coupon.active;
        await coupon.save();

        res.redirect('/coupons');
    } catch (err) {
        console.error('Error toggling coupon status:', err);
        res.redirect('/coupons');
    }
});

// POST: Delete coupon
app.post('/delete/:id', async (req, res) => {
    try {
        await Coupon.findByIdAndDelete(req.params.id);
        res.redirect('/coupons');
    } catch (err) {
        console.error('Error deleting coupon:', err);
        res.redirect('/coupons');
    }
});

// POST: Create new coupon
app.post('/create', async (req, res) => {
    try {
        const { code, discountType, discountValue, expiryDate, active } = req.body;

        if (!code || !discountType || !discountValue || !expiryDate) {
            return res.redirect('/coupons');
        }

        const existingCoupon = await Coupon.findOne({ code });
        if (existingCoupon) {
            return res.redirect('/coupons');
        }

        const coupon = new Coupon({
            code,
            discountType,
            discountValue: Number(discountValue),
            expiryDate: new Date(expiryDate),
            active: active === 'on'
        });

        await coupon.save();
        res.redirect('/coupons');
    } catch (err) {
        console.error('Error creating coupon:', err);
        res.redirect('/coupons');
    }
});

// POST: Update existing coupon
app.post('/update/:id', async (req, res) => {
    try {
        const { code, discountType, discountValue, expiryDate, active } = req.body;
        const couponId = req.params.id;

        if (!code || !discountType || !discountValue || !expiryDate) {
            return res.redirect(`/edit/${couponId}`);
        }

        const existingCoupon = await Coupon.findOne({ code, _id: { $ne: couponId } });
        if (existingCoupon) {
            return res.redirect(`/edit/${couponId}`);
        }

        await Coupon.findByIdAndUpdate(couponId, {
            code,
            discountType,
            discountValue: Number(discountValue),
            expiryDate: new Date(expiryDate),
            active: active === 'on'
        }, { new: true });

        res.redirect('/coupons');
    } catch (err) {
        console.error('Error updating coupon:', err);
        res.redirect(`/edit/${req.params.id}`);
    }
});

/////////////////////////////////////////////////////////////////////////////////////////////////////////

// fetch cart product
app.get('/cart:id', async (req, res) => {
    try {
        const cart = await Cart.find().populate('items.product'); // Fetch cart with product details
        res.render('cart', { cart }, { user: req.user }); // Pass cart data to EJS
    } catch (error) {
        res.status(500).send('Error fetching cart data');
    }
});



app.post('/add-product', 
    uploads.fields([
      { name: 'front_images', maxCount: 1 },
      { name: 'back_image', maxCount: 1 },
      { name: 'images', maxCount: 5 }
    ]),
    async (req, res) => {
      try {
        const { name, description, price, brand, color, category } = req.body;
        // console.log("the data is:",req.body,req.files)

        const sizes = {
            xsmall: parseInt(req.body.sizes?.xsmall) || 0,
            small: parseInt(req.body.sizes?.small) || 0,
            medium: parseInt(req.body.sizes?.medium) || 0,
            large: parseInt(req.body.sizes?.large) || 0,
            xlarge: parseInt(req.body.sizes?.xlarge) || 0
        };
        
        // Get uploaded file URLs from Cloudinary
        const frontImage = req.files['front_images'][0];
        const backImage = req.files['back_image'][0];
        const additionalImages = req.files['images'] || [];
  
        // Create product with Cloudinary URLs
        const product = new Product({
          name,
          description,
          sizes,
          price,
          brand,
          color,
          category,
          front_image: frontImage.path,  // Cloudinary URL
          back_image: backImage.path,    // Cloudinary URL
          images: additionalImages.map(img => img.path) // Array of Cloudinary URLs
        });
  
        await product.save();
        console.log()
        return res.send(`
            <script>
              
              window.location.href = '/add-product';
            </script>
        `);
      } catch (error) {
        console.error('Error adding product:', error);
        res.status(500).json({ 
          success: false,
          message: 'Failed to add product',
          error: error.message 
        });
      }
    }
  );
  
// Handle signup 
app.get('/signup', (req, res) => {
    res.render('signup');
});

// Handle user signup and account creation

// Route to generate and send OTP


app.post('/generate-otp', async (req, res) => {
    const { email } = req.body;

    try {
        // Check if user already exists in the database
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.send({ success: false, message: 'Email already exists. Please check the database.' });
        }

        const otp = generateOTP();
        otpCache[email] = otp; // Store OTP in cache
        sendOTP(email, otp);

        res.json({ success: true, message: 'OTP sent successfully' });

    } catch (error) {
        console.error('Error checking user:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Route to verify OTP
app.post('/verify-otp', (req, res) => {
    const { email, otp } = req.body;
    if (otpCache[email] === otp) {
        res.json({ success: true, message: 'OTP verified successfully' });
    } else {
        res.status(400).json({ success: false, message: 'Invalid OTP' });
    }
});
// Signup Route
app.post('/user/signup', async (req, res) => {
    try {
        const { name, email, phone, password, confirmPassword, otp } = req.body;

        if (password !== confirmPassword) {
            return res.status(400).send("Password and Confirm Password do not match");
        }

        // Verify OTP
        if (otpCache[email] !== otp) {
            return res.status(400).send("Invalid OTP");
        }

        // Hash the password before saving it to the database
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create a new user in the database
        const user = await User.create({ name, email, phone, password: hashedPassword });

        // console.log(user);
        res.redirect('/');

    } catch (error) {
        console.error('Error signing up user:', error);
        res.status(500).send('Error signing up user: ' + error.message);
    }
});

// Login Route
app.post('/user/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            req.session.loginError = 'Please provide both email and password';
            return res.redirect('/signup');
        }

        const user = await User.findOne({ email });

        if (!user) {
            req.session.loginError = 'Invalid email or password';
            return res.send(`
                <script>
                  alert('wrong email or password');
                  window.location.href = '/signup';
                </script>
            `);
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            req.session.loginError = 'Invalid email or password';
            return res.send(`
                <script>
                  alert('wrong email or password');
                  window.location.href = '/signup';
                </script>
            `);
     
        }

        // Create JWT token
        const SECRET_KEY = process.env.JWT_SECRET || 'Preaveen@8233';
        const token = jwt.sign({ userId: user._id }, SECRET_KEY, { expiresIn: '1h' });

        // Set session and cookies
        req.session.userId = user._id.toString();
        res.cookie('token', token, {
            httpOnly: true,
            maxAge: 3600000, // 1 hour
            secure: process.env.NODE_ENV === 'production'
        });

        // Successful login redirect
        return res.redirect('/');

    } catch (error) {
        console.error('Error logging in user:', error);
        req.session.loginError = 'Error logging in. Please try again.';
        res.redirect('/signup');
    }
});

// Handle logout
// Handle logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Could not log out, please try again');
        }
        res.clearCookie('connect.sid'); // Clear the session cookie
        res.clearCookie('userId'); // Clear the user ID cookie
        res.redirect('/');
    });
});




//apply coupon
// In your routes/cart.js
// Enhanced Coupon Application Route
// Apply Coupon Route - Now using redirects
app.post('/cart/apply-coupon', async (req, res) => {
    try {
        const { couponCode } = req.body;

        // Validate input
        if (!couponCode || typeof couponCode !== 'string' || couponCode.trim() === '') {
            req.session.couponMessage = 'Please enter a valid coupon code';
            return res.redirect('/cart');
        }

        // Get user ID
        const userId = req.user?._id || req.session.userId;
        if (!userId) {
            req.session.couponMessage = 'Please login to apply coupons';
            return res.redirect('/login'); // Redirect to login page
        }

        // Find coupon (case insensitive search)
        const coupon = await Coupon.findOne({
            code: { $regex: new RegExp(`^${couponCode.trim()}$`, 'i') },
            active: true,
            expiryDate: { $gte: new Date() }
        });

        if (!coupon) {
            // More specific error messages
            const expiredCoupon = await Coupon.findOne({
                code: { $regex: new RegExp(`^${couponCode.trim()}$`, 'i') },
                expiryDate: { $lt: new Date() }
            });

            if (expiredCoupon) {
                req.session.couponMessage = 'This coupon has expired';
                return res.redirect('/cart');
            }

            const inactiveCoupon = await Coupon.findOne({
                code: { $regex: new RegExp(`^${couponCode.trim()}$`, 'i') },
                active: false
            });

            if (inactiveCoupon) {
                req.session.couponMessage = 'This coupon is no longer active';
                return res.redirect('/cart');
            }

            req.session.couponMessage = 'Invalid coupon code';
            return res.redirect('/cart');
        }

        // Get user's cart
        const cart = await Cart.findOne({ user: userId })
            .populate('items.product')
            .populate('appliedCoupon');

        if (!cart || cart.items.length === 0) {
            req.session.couponMessage = 'Your cart is empty';
            return res.redirect('/cart');
        }

        // Check if coupon is already applied
        if (cart.appliedCoupon && cart.appliedCoupon._id.equals(coupon._id)) {
            req.session.couponMessage = 'This coupon is already applied';
            return res.redirect('/cart');
        }

        // Calculate discount
        const subtotal = cart.items.reduce((total, item) =>
            total + (item.product.price * item.quantity), 0);

        let discountAmount = 0;
        if (coupon.discountType === 'percentage') {
            discountAmount = subtotal * (coupon.discountValue / 100);
            discountAmount = Math.min(discountAmount, subtotal);
        } else {
            discountAmount = Math.min(coupon.discountValue, subtotal);
        }

        // Update cart
        cart.appliedCoupon = coupon._id;
        cart.discountAmount = discountAmount;
        await cart.save();

        req.session.couponMessage = `Coupon "${coupon.code}" applied successfully!`;
        res.redirect('/cart');

    } catch (error) {
        console.error('Coupon application error:', error);
        req.session.couponMessage = 'Failed to apply coupon';
        res.redirect('/cart');
    }
});

// Remove Coupon Route - Now using redirects
// Change from POST to GET
app.get('/cart/remove-coupon', async (req, res) => {
    try {
        const userId = req.user?._id || req.session.userId;
        if (!userId) {
            req.session.couponMessage = 'Not authorized';
            return res.redirect('/login');
        }

        const cart = await Cart.findOne({ user: userId });
        if (!cart) {
            req.session.couponMessage = 'Cart not found';
            return res.redirect('/cart');
        }

        if (!cart.appliedCoupon) {
            req.session.couponMessage = 'No coupon applied to remove';
            return res.redirect('/cart');
        }

        // Remove coupon from cart
        cart.appliedCoupon = undefined;
        cart.discountAmount = 0;
        await cart.save();

        req.session.couponMessage = 'Coupon removed successfully';
        res.redirect('/cart');

    } catch (error) {
        console.error('Error removing coupon:', error);
        req.session.couponMessage = 'Failed to remove coupon';
        res.redirect('/cart');
    }
});
// Cart Route - Updated to use session messages
app.get('/cart', async (req, res) => {
    try {
        let user = { name: "Guest" };
        let userId = null;

        // Authentication check
        if (req.user) {
            user = req.user;
            userId = req.user._id;
        } else {
            userId = req.session.userId;
            if (userId) {
                user = await User.findById(userId, "name");
            }
        }

        // Get cart with populated data
        let cart = await Cart.findOne({ user: userId })
            .populate('items.product')
            .populate('appliedCoupon');

        let discountAmount = 0;
        const couponMessage = req.session.couponMessage;
        delete req.session.couponMessage; // Clear the message after displaying

        // Validate cart and coupon
        if (cart) {
            if (!cart.items) cart.items = [];

            // Check applied coupon validity
            if (cart.appliedCoupon) {
                const now = new Date();
                if (!cart.appliedCoupon.active || cart.appliedCoupon.expiryDate < now) {
                    // Coupon is no longer valid
                    req.session.couponMessage = 'The applied coupon is no longer valid';
                    cart.appliedCoupon = undefined;
                    cart.discountAmount = 0;
                    await cart.save();
                } else {
                    discountAmount = cart.discountAmount || 0;
                }
            }
        } else {
            cart = { items: [] };
        }

        res.render('cart', {
            user,
            cart,
            discountAmount,
            message: couponMessage,
            error: null
        });

    } catch (error) {
        console.error('Error loading cart:', error);
        res.status(500).render('cart', {
            user: { name: "Guest" },
            cart: { items: [] },
            error: 'Failed to load cart'
        });
    }
});

// Add these routes to your Express app

// Update item quantity
app.post('/cart/update-quantity', async (req, res) => {
    try {
        const { productId, size, quantity } = req.body;
        let userId = req.user?._id || req.session.userId;

        if (!userId) {
            return res.status(401).json({ success: false, message: 'Not authenticated' });
        }

        const cart = await Cart.findOne({ user: userId });
        if (!cart) {
            return res.status(404).json({ success: false, message: 'Cart not found' });
        }

        // Find the item to update
        const itemIndex = cart.items.findIndex(
            item => item.product.toString() === productId && item.size === size
        );

        if (itemIndex === -1) {
            return res.status(404).json({ success: false, message: 'Item not found in cart' });
        }

        // Update quantity
        if (quantity > 0) {
            cart.items[itemIndex].quantity = quantity;
        } else {
            // Remove item if quantity is 0 or less
            cart.items.splice(itemIndex, 1);
        }

        await cart.save();
        res.json({ success: true, cart });
    } catch (error) {
        console.error('Error updating cart quantity:', error);
        res.status(500).json({ success: false, message: 'Error updating cart' });
    }
});

// Remove item from cart
app.post('/cart/remove-item', async (req, res) => {
    try {
        const { productId, size } = req.body;
        let userId = req.user?._id || req.session.userId;

        if (!userId) {
            return res.status(401).json({ success: false, message: 'Not authenticated' });
        }

        const cart = await Cart.findOne({ user: userId });
        if (!cart) {
            return res.status(404).json({ success: false, message: 'Cart not found' });
        }

        // Remove the item
        cart.items = cart.items.filter(
            item => !(item.product.toString() === productId && item.size === size)
        );

        await cart.save();
        res.json({ success: true, cart });
    } catch (error) {
        console.error('Error removing item from cart:', error);
        res.status(500).json({ success: false, message: 'Error removing item from cart' });
    }
});


app.post('/place-order', async (req, res) => {  // Changed route name
    try {
        const userId = req.user?._id || req.session.userId;

        if (!userId) {
            return res.status(401).json({ success: false, message: 'Not authenticated' });
        }

        const cart = await Cart.findOne({ user: userId })
            .populate('items.product')
            .populate('appliedCoupon');

        if (!cart || cart.items.length === 0) {
            return res.status(400).json({ success: false, message: 'Cart is empty' });
        }

        const orderItems = cart.items.map(item => ({
            product: item.product._id,
            quantity: item.quantity,
            size: item.size,
            priceAtPurchase: item.product.price
        }));

        const subtotal = cart.items.reduce((total, item) =>
            total + (item.product.price * item.quantity), 0);

        const shippingFee = 5.00;
        const discountAmount = cart.discountAmount || 0;
        const totalAmount = subtotal - discountAmount + shippingFee;

        const newOrder = new Order({
            user: userId,
            cart: cart._id,
            items: orderItems,
            subtotal,
            discountAmount,
            shippingFee,
            totalAmount,
            paymentMethod: req.body.paymentMethod || 'COD',
            paymentStatus: 'Pending',
            shippingAddress: req.body.shippingAddress,
            couponUsed: cart.appliedCoupon?._id
        });

        await newOrder.save();

        // Clear the cart
        cart.items = [];
        cart.appliedCoupon = null;
        cart.discountAmount = 0;
        await cart.save();

        res.json({
            success: true,
            orderId: newOrder._id,
            message: 'Order created successfully'
        });

    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({
            success: false,
        });
    }
});

// Order confirmation page
app.get('/confirmation/:id', async (req, res) => {
    try {
        const order = await Order.findById(req.params.id)
            .populate('user', 'name email')
            .populate('items.product', 'name price');

        if (!order) {
            return res.status(404).send('Order not found');
        }

        res.render('order-confirmation', {
            user: req.user || { name: 'Guest' },
            order
        });
    } catch (error) {
        console.error('Error fetching order:', error);
        res.status(500).send('Error loading order details');
    }
});
// Custom tshirt routes


app.post('/api/save-design', async (req, res) => {
    const { frontDesign, backDesign } = req.body;
    try {
        const design = new CustomTshirt({ frontImage: frontDesign, backImage: backDesign });
        await design.save();
        res.status(200).send('Design saved successfully');
    } catch (error) {
        console.error("Error saving design:", error);
        res.status(500).send('Error saving design');
    }
});

// View all orders (EJS)
// Get all orders for the current user
// Get all orders (without user filtering)
// GET: All Orders for Admin
app.get('/orders', async (req, res) => {
    try {
        const orders = await Order.find()
            .populate({
                path: 'items.product',
                select: 'name images price',
                // Add this to prevent null products from breaking the query
                options: { allowNull: true }
            })
            .sort({ createdAt: -1 })
            .lean();

        // Optional: Sanitize data before passing to view
        orders.forEach(order => {
            order.items = order.items.map(item => {
                if (!item.product) {
                    // Add minimal product structure if null
                    item.product = {
                        name: 'Product not available',
                        images: []
                    };
                }
                return item;
            });
        });

        res.render('order', { orders });
    } catch (error) {
        console.error('Order fetch error:', error);
        res.status(500).render('error', {
            message: 'Failed to load orders',
            error: process.env.NODE_ENV === 'development' ? error : {}
        });
    }
});

// GET: All Orders for a Logged-In User
app.get('/all-orders', async (req, res) => {
    try {
        // No need to check userId manually - attachUser middleware already did this
        if (!req.user) {
            return res.redirect('/signup');
        }

        const orders = await Order.find({ user: req.user._id })
            .populate({
                path: 'items.product',
                select: 'name images price'
            })
            .sort({ createdAt: -1 })
            .lean(); // Add lean() for better performance

        res.render('allorders', {
            orders,
            // No need to explicitly pass user - middleware handles it via res.locals
        });
    } catch (error) {
        console.error('Order fetch error:', error);
        req.flash('error', 'Failed to load orders');
        res.status(500).render('error', {
            message: 'Failed to load your orders',
            error: process.env.NODE_ENV === 'development' ? error : {}
        });
    }
});


// Get specific order details (without user checking)
app.get('/orders/:id', async (req, res) => {
    try {
        const order = await Order.findById(req.params.id)
            .populate('items.product', 'name images price description');

        if (!order) {
            return res.status(404).render('error', { message: 'Order not found' });
        }

        res.render('order_detail', { order });
    } catch (error) {
        console.error('Error fetching order details:', error);
        res.status(500).render('error', { message: 'Server error fetching order details' });
    }
});
// Get specific order details (without user checking)
app.get('/user-orders/:id', async (req, res) => {
    try {
        const order = await Order.findById(req.params.id)
            .populate('items.product', 'name images price description');

        if (!order) {
            return res.status(404).render('error', { message: 'Order not found' });
        }

        res.render('user-order_details', { order }, { user: req.user });
    } catch (error) {
        console.error('Error fetching order details:', error);
        res.status(500).render('error', { message: 'Server error fetching order details' });
    }
});


app.post('/contact', async (req, res) => {
    try {
        const { name, email, message } = req.body;

        // Basic validation
        if (!name || !email || !message) {
            return res.status(400).send('All fields are required.');
        }

        // Save to DB
        const contact = new Contact({ name, email, message });
        await contact.save();
        return res.sendFile(`<script>
            alert('Thank you for your approach, we will get back to you shortly');
              window.location.href = '/';
            </script>`)
    } catch (error) {
        console.error('Error saving contact info:', error);
        res.status(500).send('An error occurred while submitting your message.');
    }
});

// DELETE route for contact requests
app.delete('/admin/contacts/:id', async (req, res) => {
    try {
        await Contact.findByIdAndDelete(req.params.id);
        req.flash('success', 'Contact request deleted successfully');
        res.redirect('/admin/contacts');
    } catch (err) {
        console.error('Error deleting contact:', err);
        req.flash('error', 'Failed to delete contact request');
        res.redirect('/admin/contacts');
    }
});

app.get('/admin/contacts', async (req, res) => {
    try {
        const contacts = await Contact.find().sort({ submittedAt: -1 });
        res.render('contact_request', { contacts });
    } catch (err) {
        console.error('Error fetching contacts:', err);
        res.status(500).send('Internal Server Error');
    }
});


// Route to display reset password form
app.get('/reset-password/:id', async (req, res) => {
    const { id } = req.params;

    try {
        // Find the user by their ID
        const user = await User.findById(id);

        if (!user) {
            return res.status(400).send('Invalid or expired reset token');
        }

        // Token is valid, render the reset password form with userId and token
        res.render('reset_password', {
            userId: user._id,
            token: user.resetToken
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Internal server error');
    }
});

// Route to handle password reset submission
app.post('/reset-password-submit', async (req, res) => {
    const { userId, token, password } = req.body;

    try {
        const user = await User.findOne({
            _id: userId,
            resetToken: token,
            resetTokenExpiration: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).send('Invalid or expired reset token');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;

        await user.save();

        // Send a success page with alert and redirect
        return res.send(`
            <script>
              alert('Password has been reset successfully');
              window.location.href = '/signup';
            </script>
        `);
    } catch (err) {
        console.error(err);
        res.status(500).send('Something went wrong. Try again later.');
    }
});




// Route to send reset link (via email)
app.post('/reset-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.render('forget_password', { message: "Email not registered" });
        }

        // Generate a reset token and store it in the database with expiration time
        const resetToken = crypto.randomBytes(20).toString('hex');
        const resetTokenExpiration = Date.now() + 15 * 60 * 1000; // 15 minutes from now

        user.resetToken = resetToken;
        user.resetTokenExpiration = resetTokenExpiration;

        await user.save();

        // Send the reset link via email
        const resetLink = `${process.env.BASE_URL || 'http://localhost:8000'}/reset-password/${user._id}`;

        const mailOptions = {
            from: 'asusualclothing@gmail.com',
            to: email,
            subject: 'Assusal Password Reset',
            html: `
                <h2>Hello ${user.name},</h2>
                <p>Click below to reset your password:</p>
                <a href="${resetLink}">Reset Password</a>
                <p>This link will expire in 15 minutes.</p>
            `,
        };

        let transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD,
            },
            tls: {
                rejectUnauthorized: true,
            },
        });

        // Send email with the reset link
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log('Error:', error);
            } else {
                console.log('Reset Password Email sent:', info.response);
            }
        });

        res.render('forget_password', { message: "Password reset link sent to your email!" });
    } catch (err) {
        console.error(err);
        res.render('forget_password', { message: "Something went wrong. Try again later." });
    }
});



app.get('/forget-password', (req, res) => {
    res.render('forget_password', { message: "No user found with that email." });

});

// Simplified routes
app.get('/about', (req, res) => {
    res.render('aboutUs');
});
app.get('/terms-and-condition', (req, res) => {
    res.render('termsandcondition');
});

app.get('/privacy_policy', (req, res) => {
    res.render('privacypolicy');
});

app.get('/contact', (req, res) => {
    res.render('contactUs');
});



// update order status
app.post('/orders/update-status/:id', async (req, res) => {
    try {
        await Order.findByIdAndUpdate(req.params.id, { status: req.body.status });
        res.redirect('/orders');
    } catch (err) {
        console.error(err);
        res.status(500).send('Update failed');
    }
});

// Start the server on the specified port
app.listen(PORT, '0.0.0.0' , () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
