const jwt = require("jsonwebtoken");

const jwtMiddleware = (req,res,next) =>{ //Creates middleware function.
    const authHeader = req.headers["authorization"]; //Reads Authorization header from request.

    if(!authHeader){
        return res.status(401).json({message: "Token missing"})
    } //if token header is not sent, return 401 unauthorized.

    const token = authHeader.split(" ")[1]  /*Splits "Bearer token" into array:
["Bearer", "token"]
and takes token part.*/
    
    try{
        const decoded = jwt.verify(token,process.env.JWT_SECRET); //Verifies token using secret key.
        req.user = decoded; //Stores decoded payload in request object.
        next();   //Moves to next middleware or route.
    }catch(error){
        return res.status(401).json({message:"Invalid token"});  //If token is wrong or expired, return error.
    }
}
module.exports = jwtMiddleware;