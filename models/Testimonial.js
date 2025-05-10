// models/Testimonial.js
const mongoose = require("mongoose");

const testimonialSchema = new mongoose.Schema({
  name: { type: String, required: true },
  role: { type: String, required: true },
  imageUrl: { type: String, default: "" },
  quote: { type: String, required: true },
});

module.exports = mongoose.model("Testimonial", testimonialSchema);
