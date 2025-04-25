const mongoose = require("mongoose");

const CustomTshirtSchema = new mongoose.Schema({
    // userId: { type: String, required: true },
    frontImage: { type: String, required: true }, // Base64 String
    backImage: { type: String, required: true },  // Base64 String
    createdAt: { type: Date, default: Date.now }
});

const CustomTshirt = mongoose.model("CustomTshirt", CustomTshirtSchema);
module.exports = CustomTshirt;
