const router = require("express").Router();
const UserModel = require("../models/User.model");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { isAuthenticated } = require("../middleware/jwt.middleware");
const uploader = require("../middleware/cloudinary.config.js");
//Variable above ^^^^^^

//First, we need to signup a user
router.post("/signup", uploader.single("imageUrl"), async (req, res, next) => {
 // the uploader.single() callback will send the file to cloudinary and get you and obj with the url in return
 console.log('file is: ', req.file)
    
 if (!req.file) {
   console.log("there was an error uploading the file")
   next(new Error('No file uploaded!'));
   return;
 }
 
 // You will get the image url in 'req.file.path'
 // Your code to store your url in your database should be here
  const { userName, email, password } = req.body;
  //check the length of the password and that there is all the fields and password strength
  // Check if the email or password or name is provided as an empty string
  if (email === "" || password === "" || userName === "") {
    res
      .status(400)
      .json({ errorMessage: "Provide email, password and name please" });
    return;
  }

  // Use regex to validate the email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  if (!emailRegex.test(email)) {
    res.status(400).json({ message: "Provide a valid email address." });
    return;
  }

  // Use regex to validate the password format
  // const passwordRegex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  // if (!passwordRegex.test(password)) {
  //   res.status(400).json({
  //     message:
  //       "Password must have at least 6 characters and contain at least one number, one lowercase and one uppercase letter.",
  //   });
  //   return;
  // }

  try {
    const foundUser = await UserModel.findOne({ email });
    if (foundUser) {
      res.status(403).json({ message: "email already taken" });
    } else {
      //before creating a user, make sure to hash his or her password
      const mySalt = bcryptjs.genSaltSync(12);
      const hashedPassword = bcryptjs.hashSync(password, mySalt);
      const hashedUser = {
        ...req.body,
        password: hashedPassword,
        //this is where we add the actual image to the DB
        imageUrl: req.file.path,
      };

      const myNewUser = await UserModel.create(hashedUser);
      console.log("user created", myNewUser);
      const { _id, userName, email } = myNewUser;
      res.status(201).json({ _id, userName, email });
    }
  } catch (err) {
    console.log("error signing up", err);
    res.status(500).json(err);
  }
});

//Second, we need a user that signed up before to able to login
router.post("/login", async (req, res) => {
  //   const str = "Bearer lkjafldakjlfkjlakfjlkajfl;akjf";
  //   console.log(str.split(" "));

  const { email, password } = req.body;
  try {
    //first try to find a user based on the email
    const foundUser = await UserModel.findOne({ email });
    if (!foundUser) {
      res.status(400).json({
        errorMessage: "No user with that email",
      });
    } else {
      //if there is a user with that email, then we need to compare the passwords
      const doesPasswordMatch = bcryptjs.compareSync(
        password,
        foundUser.password
      );
      if (!doesPasswordMatch) {
        res.status(400).json({
          errorMessage: "Incorrect password",
        });
        //This else is for when the user exists and the password matches
      } else {
        //****************creating JWT token!!!!!******************/
        const { _id, userName } = foundUser;
        const payload = { _id, userName };
        //this is where we create a token
        //.sign method takes three arguments, data you want to save, secret string, object of options
        const authToken = jwt.sign(payload, process.env.TOKEN_SECRET, {
          algorithm: "HS256",
          expiresIn: "6h",
        });
        //This is when everything worked and now the user is logged in!
        res.status(200).json({
          message: "Congrats, you logged in",
          authToken,
        });
      }
    }
  } catch (err) {
    console.log("error logging in", err);
    res.status(500).json(err);
  }
});

//lastly a verify route
router.get("/verify", isAuthenticated, (req, res) => {
  console.log("verify route", req.payload);
  // the token is all good
  res.status(200).json(req.payload);
});

//Always remember to export your
module.exports = router;
