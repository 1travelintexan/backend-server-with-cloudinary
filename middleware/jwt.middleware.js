const { expressjwt: jwt } = require("express-jwt");

//this variable will tell us if the token is valid and not expired
//it takes four arguments
//1. secret 2. algorithm 3. name of where the data will be in the req 4. method named getToken that grabs the token from the headers

//this is the function that is going to check the headers for the token and return it if its found
const getTokenFromHeaders = (req) => {
  //check if there is something called authorization in the headers && if the first word is Bearer
  if (
    req.headers.authorization &&
    req.headers.authorization.split(" ")[0] === "Bearer"
  ) {
    const token = req.headers.authorization.split(" ")[1];
    return token;
  } else {
    return null;
  }
};
const isAuthenticated = jwt({
  secret: process.env.TOKEN_SECRET,
  algorithms: ["HS256"],
  requestProperty: "payload",
  getToken: getTokenFromHeaders,
});
module.exports = { isAuthenticated };
