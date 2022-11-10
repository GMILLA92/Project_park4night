const { Schema, model } = require("mongoose");
const spotSchema = new Schema(
    {
    name: {
        type: String,
        // required: true,
        unique: true,
        trim: true,
    },
    coordinates: {
        type: String,
        // required: true,
        unique: true,
        trim: true,
    },
    address: {
        type: String,
        required: false,
        trim: true,
    },
    province: {
        type: String,
        required: false,
    },
    rating: {
        type: Number, min: 0, max: 10,
        // required: true,
    },
    amenities: {
        type: Object,
        required: false,
        Toilet : {type: Boolean},
        BBQ : {type: Boolean},
        Electricity : {type: Boolean},
        Drinking_water: {type: Boolean},
        Trash_can: {type:Boolean},
        Shower: {type:Boolean},   
    },
    webpage: {
        type: String,
    },
    isUserFavourite: {
        type: Boolean,
        required: false,
    },
    UserSpot: { type: Schema.Types.ObjectId, ref: 'UserSpot' },
    comments: [{ type: Schema.Types.ObjectId, ref: 'Comment' }],
    description: {
        type: String,
        // required: true,
    },
    price : {
        type: Number,
        required: false,
    },
    images: {
        imagesUrl: [String],
    },
    Number_parking_spots: {
        type: Number,
        required: false,
    }
},
    {
      timestamps: true,
    }
);
  
  const Spot = model("Spot", spotSchema);
  
  module.exports = Spot;
  