// Iteration #1
const mongoose = require("mongoose")
const Spot = require("../models/Spot.model")
const Comment = require("../models/Comment.model")
const User = require("../models/User.model")
const CommentLike = require("../models/CommentLike.model")
const UserSpot = require("../models/UserSpot.model")
const bcrypt = require("bcrypt");

const MONGO_URI = "mongodb://localhost:27017/Project_park4night";




const createObjects = async function() {
    try {
        const connect = await mongoose.connect(MONGO_URI)
        console.log(`Connected to database: ${connect.connections[0].name}`)

        const deleteAll = await CommentLike.deleteMany()
        const deleteAll1 = await Comment.deleteMany()
        const deleteAll2 = await User.deleteMany()
        const deleteAll3 = await Spot.deleteMany()
        const deleteAll4 = await UserSpot.deleteMany()

        console.log("Db clean")
      

        const users = [
            {
                fullName: "Laura Cruzado",
                username: "Lcruzado92",
                email: "laura.bcn_upc@gmail.com",
                password:"$2b$10$ZZSbVKPa7S8YnIpEsF1BFOlCkHZt9CL3k81RZCJxtYtB7CH5UcO92",
                // savedSpots: [dbSpots[1]._id],
            },
            {
                fullName: "Jessica Cobo",
                username: "Jess_CF",
                email: "jess.cobo@gmail.com",
                password:"$2b$10$ZZSbVKPa7S8YnIpEsF1BFOlCkHZt9CL3k81RZCJxtYtB7CH5UcO92",
                // savedSpots: [dbSpots[0]._id,dbSpots[3]._id]
            },
            {
                fullName: "Pablo Fernández",
                username: "Ferna92",
                email: "pablito.ferna_92@gmail.com",
                password:"$2b$10$ZZSbVKPa7S8YnIpEsF1BFOlCkHZt9CL3k81RZCJxtYtB7CH5UcO92"
            }
        ]
        const dbUser = await User.create(users)
       
        const comments = [
            {
                description: "Great spot! Really quiet. You can buy food in the village and you will find electricity there as well.",
                author: dbUser[0]._id,
            },
            {
                description: "It was a bit crowded when we arrived (evening), but we could find space finally. There are restaurants near the spot, which is great!", 
                author: dbUser[1]._id, 

            },
            {
                description: "A bit noisy in the mornings when everyone goes to the beach. Though, it is worth it. Bolonia beach is just great", 
                author: dbUser[0]._id,
            },
            {
                description: "Everything perfect! I would strongly recommend this place.",
                author: dbUser[1]._id,

            },
            {
                description: "Amenities really close to the parking. We appreciated the picnic area. There is also a playground",
                author: dbUser[0]._id,                 

            },
            {
                description: "A bit disappointing. The place was really crowded",
                author: dbUser[2]._id,
            }
        
        ]
        const dbComment = await Comment.create(comments)
        
        dbComment.forEach(async (comment) => {
  
            const userUpdate = await User.findByIdAndUpdate(comment.author,{ $push: { comments: comment._id } } )
        })


        dbComment.forEach(async (comment) => {
            const randNum = Math.floor(Math.random() * 3)
            userRand = dbUser[randNum]
           
            const commentLikecr = await CommentLike.create({user: userRand._id, comment: comment._id})
            const commentUpdated = await Comment.findByIdAndUpdate(comment._id,{ $push: { commentLike: commentLikecr._id } } )

            
        })

        const allLikes = await CommentLike.find()

        allLikes.forEach(async (commentLike) => {
  
            const userUpdate = await User.findByIdAndUpdate(commentLike.user,{ $push: { commentLike: commentLike._id } } )
        })
       

        const spots = [
            {
            name: "Molló, Passeig del Vallespir", 
            coordinates: "42.348099, 2.405770",
            address: "Passeig del Vallespir, 17868 Molló Spain",
            province: "Girona",
            rating: 7,
            amenities: {
                Trash_can: true,
                
            },
            images: {
                imagesUrl: ["https://res.cloudinary.com/dfajfbnkr/image/upload/v1667818518/AIRBnvan/Mollo_spot3_l7kims.jpg", "https://res.cloudinary.com/dfajfbnkr/image/upload/v1667818518/AIRBnvan/Mollo_spot2_aoziwr.jpg", "https://res.cloudinary.com/dfajfbnkr/image/upload/v1667818518/AIRBnvan/Mollo_spot1_fwesbu.jpg"]
            },
            description: "Free parking for vans in a quiet zone. Perfect spot for hiking! You can find drinking water close to the parking (in the village main square)",
            Number_parking_spots: 20,
            comments: [dbComment[0]._id, dbComment[3]._id]
            },
            {
            name: "Tarifa, Pista Vereda de la Reginosa", 
            coordinates: "36.087044, -5.769359",
            address: "Pista Vereda de la Reginosa, 11391 Tarifa Spain",
            province: "Cádiz",
            rating: 8,
            amenities: {
                Trash_can: true,
                Shower: true,
                Toilet: false,   
            },
            images: {
                imagesUrl: ["https://res.cloudinary.com/dfajfbnkr/image/upload/v1667819217/AIRBnvan/tarifa_spot1_dqubzu.jpg","https://res.cloudinary.com/dfajfbnkr/image/upload/v1667819112/AIRBnvan/tarifa_spot2_ydwvkl.jpg"],
            },
            description: "Free parking for vans next to Bolonia beach.",
            Number_parking_spots: 20,
            comments: [dbComment[1]._id, dbComment[2]._id]
            },
            {
            name: "Gijón, Camin de Peñarrubia", 
            coordinates: "43.549198, -5.623890",
            address: "Camin de Peñarrubia, 33203 Gijón Spain",
            province: "Asturias",
            rating: 6,
            amenities: {
                Trash_can: true,
            },
            images: {
                imagesUrl: ["https://res.cloudinary.com/dfajfbnkr/image/upload/v1667820422/AIRBnvan/guijon_spot1_erlhmg.jpg","https://res.cloudinary.com/dfajfbnkr/image/upload/v1667820422/AIRBnvan/guijon_spot2_wrdqm8.jpg"],
            },
            description: "Parking close to Penurubbia beach. No drinking water, no toilets and no showers, but beautiful views of the seacost!",
            Number_parking_spots: 50,
            comments: [dbComment[5]._id]
            },
            {
            name: "Es Mercadal parking spot", 
            coordinates: "40.032512, 4.192128",
            address: "34 Urbanització Punta Grossa, Polígon II, 07740 Es Mercadal",
            province: "Menorca",
            rating: 7,
            images: {
                imagesUrl: ["https://res.cloudinary.com/dfajfbnkr/image/upload/v1667821338/AIRBnvan/menorca_spot3_dcff3w.jpg","https://res.cloudinary.com/dfajfbnkr/image/upload/v1667821338/AIRBnvan/menorca_spot2_ncjy5m.jpg"],
            },
            description: "No amenities. Cliffs with amazing sea views. Easy access accross an unpaved road",
            comments: [dbComment[3]._id]
            },
            {
            name: "Bentabarri Kalea parking", 
            coordinates: "42.957370, -2.591214",
            address: "1 Bentabarri Kalea, 01520 Spain",
            province: "Bizcaia",
            rating: 9,
            images: { 
                imagesUrl: ["https://res.cloudinary.com/dfajfbnkr/image/upload/v1667821041/AIRBnvan/euskadi_spot1_lb0wun.jpg","https://res.cloudinary.com/dfajfbnkr/image/upload/v1667821041/AIRBnvan/euskadi_spot2_d58m6c.jpg","https://res.cloudinary.com/dfajfbnkr/image/upload/v1667821041/AIRBnvan/euskadi_spot3_g1ncz8.jpg"],
            },
            description: "Perfect spot! A lot of amenities next to the parking. The best part was the picnic area.",
            amenities: {
                Trash_can: true,
                Shower: true,
                Drinking_water: true,
                Toilet: true,
            },
            Number_parking_spots: 25,
            comments: [dbComment[4]._id]
            }
        ];
        const dbSpots = await Spot.create(spots)
       
        
        const userSpot = await UserSpot.create({user: dbUser[0]._id, spot: dbSpots[0]._id })
        const userSpot2 = await UserSpot.create({user: dbUser[1]._id, spot: dbSpots[1]._id })
        const userSpot3 = await UserSpot.create({user: dbUser[1]._id, spot: dbSpots[3]._id })
        const userSpot4 = await UserSpot.create({user: dbUser[2]._id, spot: dbSpots[2]._id})

        const userUpdate1 = await User.findByIdAndUpdate(dbUser[0]._id,{ $push: { UserSpot: userSpot._id } } )
        const userUpdate2 = await User.findByIdAndUpdate(dbUser[1]._id,{ $push: { UserSpot: userSpot2._id } } )
        const userUpdate3 = await User.findByIdAndUpdate(dbUser[1]._id,{ $push: { UserSpot: userSpot3._id } } )
        const userUpdate4 = await User.findByIdAndUpdate(dbUser[2]._id,{ $push: { UserSpot: userSpot4._id } } )
           
        const spotUpdate1 = await Spot.findByIdAndUpdate(dbSpots[0]._id,{ $push: { UserSpot: userSpot._id } } )
        const spotUpdate2 = await Spot.findByIdAndUpdate(dbSpots[1]._id,{ $push: { UserSpot: userSpot2._id } } )
        const spotUpdate3 = await Spot.findByIdAndUpdate(dbSpots[2]._id,{ $push: { UserSpot: userSpot4._id } } )
        const spotUpdate4 = await Spot.findByIdAndUpdate(dbSpots[3]._id,{ $push: { UserSpot: userSpot3._id } } )

        const dbClose = await mongoose.connection.close()
        console.log("Connection closed")

    }catch (err) {
      console.log(`Error creating the seeds: ${err}`)
    }
}
  
createObjects()







