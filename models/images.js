const mongoose = require('mongoose');

const imageSchema = new mongoose.Schema({
    name: String,
    data: String, // Store the Base64 encoded string here
});

module.exports = mongoose.model('Image', imageSchema);