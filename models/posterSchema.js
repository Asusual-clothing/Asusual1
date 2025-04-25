const mongoose = require('mongoose');

const PosterSchema = new mongoose.Schema({
    image: {
        type: [String], // Store base64 image as a string
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    Heading:{ type: [String], default:"As Usual"},
    Title:{
        type: [String], default: "Style is casual, Asusual"
    }

});

module.exports = mongoose.model('Poster', PosterSchema);