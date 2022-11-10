const { Schema, model } = require("mongoose");

const userSchema = new Schema(
  {
    fullName: {
      type: String,
      required: true,
      trim:true,
    },
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
    password: {
      type: String,
      required: true,
    },
    favouriteSpots: [{
      type: Schema.Types.ObjectId,
      ref: 'Spot'
    }],
    UserSpot: [{ type: Schema.Types.ObjectId, ref: 'UserSpot' }],
    comments: [{ type: Schema.Types.ObjectId, ref: 'Comment' }],
    commentLike: [{ type: Schema.Types.ObjectId, ref: 'CommentLike' }]
  },
  { 
    timestamps: true,
  }
);

const User = model("User", userSchema);

module.exports = User;
