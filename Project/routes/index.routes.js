const express = require('express');
const isLoggedOut = require('../middleware/isLoggedOut');
const router = express.Router();
const Spot = require("../models/Spot.model")

/* GET home page */
router.get("/", async (req, res, next) => {
  try{
    const spotsDb = await Spot.find()
    const mapCenter = [-3.703339, 40.416729]
    const mapZoom = 5
    res.render("index", {layout:false, user: req.session.currentUser, spotsDb, mapCenter, mapZoom});  
  }catch(err){
    console.log(err)
  }
});

module.exports = router;
