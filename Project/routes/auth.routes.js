const express = require("express");
const router = express.Router();
const fileUploader = require('../config/cloudinary.config');
// ℹ️ Handles password encryption
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");

// How many rounds should bcrypt run the salt (default - 10 rounds)
const saltRounds = 10;

// Require the User model in order to interact with the database
const User = require("../models/User.model");

// Require necessary (isLoggedOut and isLiggedIn) middleware in order to control access to specific routes
const isLoggedOut = require("../middleware/isLoggedOut");
const isLoggedIn = require("../middleware/isLoggedIn");

// Require the Spot & UserSpot model in order to interact with the database
const Spot = require("../models/Spot.model")
const UserSpot = require("../models/UserSpot.model")
const Comment = require("../models/Comment.model")
const CommentLike = require("../models/CommentLike.model")


// GET /auth/signup
router.get("/signup", isLoggedOut, (req, res) => {
  res.render("auth/signup", { layout: false });
});

// POST /auth/signup
router.post("/signup", isLoggedOut, (req, res) => {
  const { fullName, username, email, password } = req.body;
  console.log(req.body)

  // Check that username, email, and password are provided
  if (username === "" || email === "" || password === "") {
    res.status(400).render("auth/signup", {
      errorMessage:
        "All fields are mandatory. Please provide your username, email and password.",
      layout: false
    });

    return;
  }

  if (password.length < 6) {
    res.status(400).render("auth/signup", {
      errorMessage: "Your password needs to be at least 6 characters long.",
      layout: false
    });

    return;
  }

  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (!regex.test(password)) {
    res
      .status(400)
      .render("auth/signup", {
        errorMessage: "Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.",
        layout: false
      });
    return;
  }


  // Create a new user - start by hashing the password
  bcrypt
    .genSalt(saltRounds)
    .then((salt) => bcrypt.hash(password, salt))
    .then((hashedPassword) => {
      // Create a user and save it in the database
      return User.create({ fullName, username, email, password: hashedPassword });
    })
    .then((user) => {
      res.redirect("/profile");
    })

    .catch((error) => {
      if (error instanceof mongoose.Error.ValidationError) {
        res.status(500).render("auth/signup", { errorMessage: error.message, layout: false });
      } else if (error.code === 11000) {
        res.status(500).render("auth/signup", {
          errorMessage:
            "Username and email need to be unique. Provide a valid username or email.",
          layout: false
        });
      } else {
        next(error);
      }
    });

});

// GET /auth/login
router.get("/login", isLoggedOut, (req, res) => {
  res.render("auth/login", { layout: false });
});

// POST /auth/login
router.post("/login", isLoggedOut, (req, res, next) => {
  const { username, email, password } = req.body;

  // Check that username, email, and password are provided
  if (username === "" || email === "" || password === "") {
    res.status(400).render("auth/login", {
      errorMessage:
        "All fields are mandatory. Please provide username, email and password.",
      layout: false
    });

    return;
  }

  // Here we use the same logic as above
  // - either length based parameters or we check the strength of a password
  if (password.length < 6) {
    return res.status(400).render("auth/login", {
      errorMessage: "Your password needs to be at least 6 characters long.",
      layout: false
    });
  }

  // Search the database for a user with the email submitted in the form
  User.findOne({ email })
    .then((user) => {
      // If the user isn't found, send an error message that user provided wrong credentials
      if (!user) {
        res
          .status(400)
          .render("auth/login", { errorMessage: "Wrong credentials.", layout: false });
        return;
      }

      // If user is found based on the username, check if the in putted password matches the one saved in the database
      bcrypt
        .compare(password, user.password)
        .then((isSamePassword) => {
          if (!isSamePassword) {
            res
              .status(400)
              .render("auth/login", { errorMessage: "Wrong credentials.", layout: false });
            return;
          }

          // Add the user object to the session object
          req.session.currentUser = user.toObject();
          // Remove the password field
          delete req.session.currentUser.password;

          res.redirect("/map");
        })
        .catch((err) => next(err)); // In this case, we send error handling to the error handling middleware.
    })
    .catch((err) => next(err));
});

// GET /auth/logout
router.post("/logout", isLoggedIn, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      res.status(500).redirect("/")
      return;
    }

    res.redirect("/");
  });
});



//GET /users/user-profile
router.get("/profile", isLoggedIn, (req, res) => {
  res.render("users/user-profile", req.session.currentUser);

});


//GET /spots/addSpot
router.get("/addSpot", (req, res) => {
  res.render("spots/addSpot");
});

router.post("/addSpot", fileUploader.array('images'), async (req, res) => {
  const { name, coordinates, address, description, province, rating, webpage, BBQ, Toilet, Electricity, Trash_can, Drinking_water, Shower } = req.body;
  console.log(req)
  const images = { imagesUrl: [] }
  if (req.file) {
    images.imagesUrl.push(req.file.path)
  } else if (req.files) {
    req.files.forEach((file) => {
      images.imagesUrl.push(file.path)
    })
  }

  const amenities = {}
  if (BBQ) { amenities.BBQ = true }
  if (Toilet) { amenities.Toilet = true }
  if (Electricity) { amenities.Electricity = true }
  if (Trash_can) { amenities.Trash_can = true }
  if (Drinking_water) { amenities.Drinking_water = true }
  if (Shower) { amenities.Shower = true }

  
    try {
      const newSpot = await Spot.create({ name, coordinates, address, images, description, province, amenities, rating, webpage })
      console.log("Spot Created")

      res.redirect("/map")
    } catch(err){
        if (err instanceof mongoose.Error.ValidationError) {
          res.status(500).render("spots/addSpot",  { errorMessage: err.message, layout: false });
        } else if (err.code === 11000) {
          res.status(500).render("spots/addSpot", {
            errorMessage:
              "The name of the spot and the coordinates should be unique",
              layout: false
          });
        } else {
          next(err);
        }

      console.log(err)
    
    }
  
  })

router.get("/savedSpots", async (req, res) => {
  console.log("hola")
  //  console.log(req.session.currentUser)
  const UserSaved = await User.findById(req.session.currentUser._id).populate("favouriteSpots")
  console.log('USUARIO', UserSaved.favouriteSpots)
  // console.log(UserSaved.UserSpot[0].spot.comments[0].author)
  // const result = await UserSpot.findById(UserSaved.UserSpot._id).populate("spot")
  //console.log(UserSaved)
  // console.log(UserSaved.UserSpot[0].spot.images)

  res.render("spots/list-saved-spots", UserSaved);
});

//GET /spots/spot
router.get("/spot/:spotId", async (req, res) => {
  const spotId = req.params.spotId
  try {
    const dbSpot = await Spot.findById(spotId).populate("comments").populate({
      path: "comments",
      populate: {
        path: "author",
        model: "User",
      }
    })

    const user = await User.findById(req.session.currentUser._id)

    dbSpot.isUserFavourite = user.favouriteSpots.includes(dbSpot._id)

    console.log(dbSpot)
    res.render("spots/spot-details", dbSpot)
  } catch (err) {
    console.log(err)
  }
})

//GET 
router.get("/map", isLoggedIn, async (req, res) => {
  try {
    const spotsDb = await Spot.find()
    const mapCenter = [-3.703339, 40.416729]
    const mapZoom = 5
    res.render("map", { layout: false, user: req.session.currentUser, spotsDb, mapCenter, mapZoom });
  } catch (err) {
    console.log(err)
  }
});



router.get("/addComment/:spotID", (req, res) => {
  console.log(req.body)

  res.render("comments/addComment", { spotID: req.params.spotID });

});

router.post("/publishComment/:spotID", async (req, res) => {

    try{
      const authorSaved = await User.findById(req.session.currentUser._id)
      const spotSaved = await Spot.findById(req.params.spotID)
      const comment = {
        spot: spotSaved,
        author: authorSaved,
        description: req.body.description
      }
      
      const newComment = await Comment.create(comment)
      await  Spot.findByIdAndUpdate(req.params.spotID, { $push: { comments: newComment._id } });
      await  User.findByIdAndUpdate(req.session.currentUser._id, { $push: { comments: newComment._id } });

      console.log("Comment Created")
      res.redirect("/map")
    } catch(err){
      console.log(err)
    }
})

router.get("/addLike/:commentID", async (req, res) => {
  try{
   
    const commentSaved = await Comment.findById(req.params.commentID)
    const user1 = await User.findById(req.session.currentUser._id).populate("commentLike")
   
    let found = 0
   
    user1.commentLike.forEach ((element) => {
      if (element.comment._id = commentSaved._id){
        found = 1;
      }
    })
 
    if (found === 1){
      res.redirect("/map")
    } else{

      const Like = {
      comment: req.params.commentID,
      user: req.session.currentUser._id,
      }
      const newLike = await CommentLike.create(Like)
      const comment = await Comment.findByIdAndUpdate(req.params.commentID, { $push: { commentLike: newLike._id } } )
      const user2 = await User.findByIdAndUpdate(req.session.currentUser._id, { $push: { commentLike: newLike._id } } )
    
      res.redirect("/savedSpots")
  }
  }catch(err){
    console.log(err)
  }

});

router.post('/:spotId/saveFavouriteSpot', async (req, res) => {
  if (!req.session?.currentUser?._id) return res.status(403).json({
    message: 'Missing user session Id'
  })

  const user = await User.findById(req.session.currentUser._id)
  console.log('before if', user.favouriteSpots.includes(req.params.spotId))
  if (!user.favouriteSpots.includes(req.params.spotId)) {

    user.favouriteSpots.push(req.params.spotId)
  } else {
    console.log('user.favouriteSpots', user.favouriteSpots)
    user.favouriteSpots = user.favouriteSpots.filter(fspot => fspot.toString() !== req.params.spotId)
    console.log('user.favouriteSpots 2', user.favouriteSpots)  
  }
  await user.save()
  res.redirect("/savedSpots")
  return res.status(200)

})



module.exports = router;
