const express = require("express");
const router = express.Router();

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
  res.render("auth/signup", {layout:false});
});

// POST /auth/signup
router.post("/signup", isLoggedOut, (req, res) => {
  const {fullName, username, email, password } = req.body;
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
    layout: false});
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
        res.status(500).render("auth/signup",  { errorMessage: error.message, layout: false });
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
  res.render("auth/login", {layout:false});
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

          res.redirect("/");
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
  res.render("users/user-profile", req.session.currentUser );
  
});





  
//GET /spots/addSpot
router.get("/addSpot", (req, res) => {
  res.render("spots/addSpot");
});

router.post("/addSpot", async (req, res) => {
  const {name, coordinates, images, description, amenities, webpage} = req.body;
  console.log(req.body)
  try{
    const newSpot = await Spot.create({name, coordinates, images, description, amenities, webpage })
    console.log("Spot Created")
    res.redirect("/")
  } catch(err){
    console.log(err)
  }
})

router.get("/savedSpots" ,async (req, res) => {
  console.log("hola")
//  console.log(req.session.currentUser)
  const UserSaved = await User.findById(req.session.currentUser._id).populate("UserSpot ").populate({
    path: "UserSpot",
    populate: {
      path: "spot",
      model: "Spot",
      populate: {
        path: "comments",
        model: "Comment",
        populate: {
          path: "author",
          model: "User",
          populate: {
            path: "commentLike",
            model: "CommentLike"
          }
        }
      }
    }
  })

  console.log(UserSaved.UserSpot[0].spot.comments[0].author)
  // const result = await UserSpot.findById(UserSaved.UserSpot._id).populate("spot")
  //console.log(UserSaved)
  

  res.render("spots/list-spots", UserSaved );
});
//GET /spots/spot
router.get("/:spotId", async (req, res) => {
  const spotId = req.params.spotId
  try {
    const spot = await Spot.findById(spotId)
    console.log(spot)
    res.render("spots/spot", spot)
  }catch (err) {
    console.log(err)
  }
})





module.exports = router;
