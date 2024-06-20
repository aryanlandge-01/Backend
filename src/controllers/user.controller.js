import {asyncHandler} from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js";
import {User} from "../models/user.model.js";
import {uploadOnCloudinary} from "../utils/cloudinary.js";
import {ApiResponse} from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshToken = async(userId) => {
    try {
       const user = await User.findById(userId);
       const accessToken = user.generateAccessToken()
       const refreshToken = user.generateRefreshToken()

       user.refreshToken = refreshToken;
       await user.save({validateBeforeSave: false})

       return {accessToken,refreshToken}

    } catch (error) {
        throw new ApiError(500,"something went wrong while generation refresh and access token")
    }
}

const registerUser = asyncHandler( async (req,res) => {
   
    const {fullName,email,username,password} = req.body

    // console.log("Email: ", email);

    if (
        [fullName,email,username,password].some((field) => 
           field?.trim() === ""
        )
    ) {
        throw new ApiError(400,"All field are required")
    } 

    const existedUser = await User.findOne({
        $or: [{username},{email}]
    })

    if (existedUser) {
        throw new ApiError(409,"User with email or username already exists")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;
    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0]?.path
    }

    if (!avatarLocalPath) {
        throw new ApiError(400,"Avatar file is required")
    }
    // file upload on cloud
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);
    
    if (!avatar) {
        throw new ApiError(400,"Avatar file is required")
    }

    // user is created in mongodb
    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || " ",
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if (!createdUser) {
        throw new ApiError(500,"Something went wrong while registring the user.")
    }

    return res.status(201).json(
        new ApiResponse(200,createdUser,"User registered Successfully")
    )


})

const loginUser = asyncHandler(async (req,res) => {
    const {email,username,password} = req.body

    // console.log(email);
    
    if (!username && !email) {
        throw new ApiError(400,"username or email is required")
    }

    const user = await User.findOne({
        $or: [{username},{email}]
    })

    if (!user) {
        throw new ApiError(404,"user does not exits")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)
    
    if (!isPasswordValid) {
        throw new ApiError(401,"Invalid user credentials")
    }

    const {accessToken,refreshToken} = await generateAccessAndRefreshToken(user._id);
    
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(
            200,
            {
                user: loggedInUser,accessToken,refreshToken
            },
            "user logged in successfully"
        )
    )

      

})

const logoutUser = asyncHandler(async(req,res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(new ApiResponse(200,{},
        "user logout successfully"
    ))


})

const refreshAccessToken = asyncHandler(async(req,res) => {
   const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
   
   if (!incomingRefreshToken) {
    throw new ApiError(401,"unauthorized request")
   }

   try {
    const decodedToken = jwt.verify(
        incomingRefreshToken,
        process.env.REFRESH_TOKEN_SECRET
    )
 
    const user = await User.findById(decodedToken?._id);
    
    if (!user) {
     throw new ApiError(401,"Invalid refresh Token")
    }
 
    if (incomingRefreshToken !== user?.refreshToken) {
     throw new ApiError(401,"Refresh token is expired or used")
    }
 
    const options = {
     httpOnly: true,
     secure: true
    }
 
    const {accessToken,newrefreshToken} = await generateAccessAndRefreshToken(user._id)
 
    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",newrefreshToken,options)
    .json(
     new ApiResponse(
         200,
         {accessToken,refreshToken: newrefreshToken},
         "Access token refreshed"
     )
    )
   } catch (error) {
      throw new ApiError(401,error?.message || "Invalid Refresh Token")
   }


})

export {registerUser,loginUser,logoutUser,refreshAccessToken}


// for registration of user 
// step 1: Take a data input 
// step 2: validation
// step 3: check if user already exits : username, email
// step 4: check for images, check for avatar 
// step 5: upload them to cloudinary, avatar
// step 6: create user object - create entry in db
// step 7: remove password and refresh token field from response
// step 8: check for user creation 
// step 9: check for response and return 

// for login the user 

/*
 step 1: Take the data input
 step 2: validation
 step 3: check if user already exists : email ,password
 step 4: send to the register page
 step 5: If the user exist return true and login the user
*/

//tutor ka hai
/* 
   req body -> data
   username or email
   find the user 
   password check 
   access and refresh token generation
   send cookies
   send the response
*/