// Import necessary modules
const dbConnection = require("../db/dbConfig"); // Database connection
const bcrypt = require("bcrypt"); // For hashing passwords
const crypto = require("crypto"); // For generating secure tokens; built in package in node.js
const jwt = require("jsonwebtoken"); // For generating JWT tokens
const { StatusCodes } = require("http-status-codes");
const mailer = require("../utils/mailer"); // a mailer utility for sending emails
const rateLimit = require("express-rate-limit"); // For rate limiting email requests


// Rate limiter for email requests (to prevent spam)
const emailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit to 5 requests per windowMs
  message: { msg: "Too many password reset requests from this IP, please try again later" },
});

// Helper function for email validation
function isValidEmail(email) {
  const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
  return emailRegex.test(email);
}

// I) Register user
async function register(req, res) {
  const { username, firstname, lastname, email, password } = req.body;

  if (!username || !firstname || !lastname || !email || !password) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "please provide all the required information" });
  }

  if (!isValidEmail(email)) {
  return res
    .status(StatusCodes.BAD_REQUEST)
    .json({ msg: "Invalid email format" });
}


  try {
    const [user] = await dbConnection.query(
      "SELECT username, userid FROM users WHERE username=? or email=?",
      [username, email]
    );

    if (user.length > 0) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "username already registered" });
    }

    if (password.length < 8) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "password must be at least 8 characters" });
    }

    // Encrypt the password
    const salt = await bcrypt.genSalt(12); //increased salt rounds from 10 to 12 for better security 
    const hashedPassword = await bcrypt.hash(password, salt);

    await dbConnection.query(
      "INSERT INTO users (username, firstname, lastname, email, password) VALUES (?,?,?,?,?)",
      [username, firstname, lastname, email, hashedPassword]
    );

    return res.status(StatusCodes.CREATED).json({ msg: "user registered successfully" });
  } catch (error) {
    console.error("Error during registration:", error.message); // Log the error to the console
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "something went wrong, try again later" });
  }
}

// II) Login user
async function login(req, res) {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "please provide all the required information" });
  }
// store User's un, uid, pw from db as array ?mine: to differentiate from the destructred one from req.body
  try {
    const [user] = await dbConnection.query(
      "SELECT username, userid, password FROM users WHERE email=?",
      [email]
    );

    if (user.length === 0) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "invalid credentials" });
    }

    // Compare passwords:  password from req.body with user[0].password from db
    const isMatch = await bcrypt.compare(password, user[0].password);

    if (!isMatch) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "invalid credentials" });
    }

    const username = user[0].username;
    const userid = user[0].userid;
    const token = jwt.sign({ username, userid }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    return res
      .status(StatusCodes.OK)
      .json({ msg: "user login successful", token, username });
  } catch (error) {
    console.error("Error during login:", error.message); // Log the error to the console
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "something went wrong, try again later" });
  }
}

// III) Check user (authentication check)
// req.user is set by an authentication middleware (like passport, or a custom JWT middleware) and contains the data of the authenticated user based on the token provided in the request header (often in Authorization).

async function check(req, res) {
  const { username, userid } = req.user;

  res.status(StatusCodes.OK).json({ msg: "valid user", username, userid });
}

// IV) Password reset request (Step 1: Requesting the password reset)
async function requestPasswordReset(req, res) {
  //  
  const { email } = req.body;
  
 if (!isValidEmail(email)) {
   return res
     .status(StatusCodes.BAD_REQUEST)
     .json({ msg: "Invalid email format" });
 }

  try {
    // Apply rate limit to prevent email spam and get user values from db based on email from req.body
    emailLimiter(req, res, async () => {
      const [user] = await dbConnection.query(
        "SELECT * FROM users WHERE email=?",
        [email]
      );

      if (user.length === 0) {
        return res
          .status(StatusCodes.BAD_REQUEST)
          .json({ msg: "Email not found" });
      }

      // 2) Generate a password reset token (20 bytes length)
      const resetToken = crypto.randomBytes(20).toString("hex");

      const resetTokenExpiration = Date.now() + (60*60* 1000) ; // 1 hour expiration time  60 min x 60 sec x 1000 ms
      
      console.log(`calculated resetTokenExpiration: ${resetTokenExpiration}`);

      try {
        // 3) Save the reset token and its expiration in the database
        await dbConnection.query(
          "UPDATE users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE email = ?",
          [resetToken, resetTokenExpiration, email]
        );

        const [result] = await dbConnection.query(
          "SELECT resetPasswordExpires FROM users WHERE email = ?",
          [email]
        );

        if (result && result.length > 0) {
          // Access the first (and possibly only) row
          console.log(`resetPWExpiryTime: ${result[0].resetPasswordExpires}`);
          if (result[0].resetPasswordExpires = resetTokenExpiration ){
            console.log("these times are equal")
          } else {console.log("these times are not equal")}
        } else {
          // Handle the case where no user was found for the email
          console.log("No user found with the given email.");
        }
        // Send reset email with reset link (make sure you have a mailer function to send the email) // this is plain text (not HTML formatted)
        const resetLink = `http://localhost:5173/resetPassword/${resetToken}`; // Adjusted based on your frontend's URL for the reset page
        
        await mailer.sendPasswordResetEmail(email, resetLink);

        return res.status(StatusCodes.OK).json({
          status: "success",
          msg: "Password reset link sent to your email",
        });
      } catch (error) {
        
        // // Clear token and expiration if anything goes wrong
        // await dbConnection.query(
        //   "UPDATE users SET resetPasswordToken = NULL, resetPasswordExpires = NULL WHERE email = ?",
        //   [email]
        // );

        console.error("Error during password reset request:", error); 
        return res
          .status(StatusCodes.INTERNAL_SERVER_ERROR)
          .json({ msg: "Error occurred. Please try again." });
      }
    });
  } catch (error) {
    console.error("Error during password reset request: " + error.message); // Logging the error
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "Error occurred. Please try again." });
  }
}

// V) Validate reset token (Step 2: Backend validates the token)
async function validateResetToken(req, res) {
  console.log("Inside validateResetToken function"); // Log added to check if this function is being called
  
  const { token } = req.body;

  try {
    // Find user by PwResettoken ; (Validate token, check expiration, etc.)
    const [user] = await dbConnection.query(
      "SELECT * FROM users WHERE resetPasswordToken = ?",
      [token]
    );


const [result] = await dbConnection.query(
  "SELECT resetPasswordExpires FROM users WHERE resetPasswordToken = ?",
  [token]
);

if (result && result.length > 0) {
  
  // Access the first (and possibly only) row
  console.log(`resetPWExpiryTime1: ${result[0].resetPasswordExpires}`);
  if ((result[0].resetPasswordExpires > Date.now())) {
    console.log("resetPWExpiryTime1 is greater");
  } else {
    console.log("resetPWExpiryTime1 is not greater");
  }
} else {
  // Handle the case where no user was found for the email
  console.log("No user found with the given email.");
}


    // Log current date and resetPasswordExpires date for debugging
   
    console.log(`Date Now: ${Date.now()}`); // Logs current timestamp
    if (user) {
      console.log(`resetPwExpiration: ${user.resetPasswordExpires}`); // Logs the reset token expiration timestamp
    } 

    // if no user found using reset pwResetToken or pwResetToken has expired
    if (!user || result[0].resetPasswordExpires < Date.now()) {
      // Clear expired token from the database
      await dbConnection.query(
        "UPDATE users SET resetPasswordToken = NULL, resetPasswordExpires = NULL WHERE resetPasswordToken = ?",
        [token]
      );

      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "Invalid or expired token" });
    }
    
    return res.status(StatusCodes.OK).json({ msg: "Valid token" });
  } catch (error) {
    console.error("Error during reset token validation:", error.message); // Log the error to the console
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "Error occurred. Please try again later" });
  }
}


// VI) Password reset (Step 3: Resetting the password with token)
async function resetPassword(req, res) {
  const { token } = req.params; // This will get the token from the URL
  const { newPassword, confirmPassword } = req.body;

  if (newPassword !== confirmPassword) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: "Passwords do not match" });
  }

  // console.log("Received reset password request with token:", token);

  try {
    // Find user by reset token and ensure the token has not expired
    const [user] = await dbConnection.query(
      "SELECT * FROM users WHERE resetPasswordToken = ? AND resetPasswordExpires > ?",
      [token, Date.now()]
    );

    if (user.length === 0) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ msg: "Invalid or expired token" });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update the user's password and clear reset token fields
    await dbConnection.query(
      "UPDATE users SET password = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL WHERE email = ?",
      [hashedPassword, user[0].email]
    );

    // Automatically log in the user after password reset

    const username = user[0].username;
    const userid = user[0].userid;
    const logintoken = jwt.sign({ username, userid }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    return res
      .status(StatusCodes.OK)
      .json({
        msg: "Password has been successfully reset",
        token: logintoken,
        username,
      });
  } catch (error) {
    console.error("Error during password reset:", error); // More detailed error logging
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ msg: "Error occurred. Please try again." });
  }
}

module.exports = {
  register,
  login,
  check,
  requestPasswordReset, // Ensure this is exported for password reset request
  validateResetToken, // Added this function to the export for token validation
  resetPassword, // Ensure this is exported for password reset
};

// // Import necessary modules
// const dbConnection = require("../db/dbConfig"); // Database connection
// const bcrypt = require("bcrypt"); // For hashing passwords
// const crypto = require("crypto"); // For generating secure tokens
// const jwt = require("jsonwebtoken"); // For generating JWT tokens
// const { StatusCodes } = require("http-status-codes");
// const mailer = require("../utils/mailer"); // a mailer utility for sending emails

// // Register user
// async function register(req, res) {
//   const { username, firstname, lastname, email, password } = req.body;

//   if (!username || !firstname || !lastname || !email || !password) {
//     return res
//       .status(StatusCodes.BAD_REQUEST)
//       .json({ msg: "please provide all the required informations" });
//   }

//   try {
//     const [user] = await dbConnection.query(
//       "SELECT username, userid FROM users WHERE username=? or email=?",
//       [username, email]
//     );

//     if (user.length > 0) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "username already registered" });
//     }

//     if (password.length < 8) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "password must be at least 8 characters" });
//     }

//     // Encrypt the password
//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(password, salt);

//     await dbConnection.query(
//       "INSERT INTO users (username, firstname, lastname, email, password) VALUES (?,?,?,?,?)",
//       [username, firstname, lastname, email, hashedPassword]
//     );

//     return res.status(StatusCodes.CREATED).json({ msg: "user registered" });
//   } catch (error) {
//     console.log(error.message);
//     return res
//       .status(StatusCodes.INTERNAL_SERVER_ERROR)
//       .json({ msg: "something went wrong, try again later" });
//   }
// }

// // Login user
// async function login(req, res) {
//   const { email, password } = req.body;

//   if (!email || !password) {
//     return res
//       .status(StatusCodes.BAD_REQUEST)
//       .json({ msg: "please provide all the required informations" });
//   }

//   try {
//     const [user] = await dbConnection.query(
//       "SELECT username, userid, password FROM users WHERE email=?",
//       [email]
//     );

//     if (user.length === 0) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "invalid credentials" });
//     }

//     // Compare password
//     const isMatch = await bcrypt.compare(password, user[0].password);

//     if (!isMatch) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "invalid credentials" });
//     }

//     const username = user[0].username;
//     const userid = user[0].userid;
//     const token = jwt.sign({ username, userid }, process.env.JWT_SECRET, {
//       expiresIn: "1d",
//     });

//     return res
//       .status(StatusCodes.OK)
//       .json({ msg: "user login successful", token, username });
//   } catch (error) {
//     console.log(error.message);
//     return res
//       .status(StatusCodes.INTERNAL_SERVER_ERROR)
//       .json({ msg: "something went wrong, try again later" });
//   }
// }

// // Check user (authentication check)
// async function check(req, res) {
//   const username = req.user.username;
//   const userid = req.user.userid;

//   res.status(StatusCodes.OK).json({ msg: "valid user", username, userid });
// }

// // Password reset request (Step 1: Requesting the password reset)
// async function requestPasswordReset(req, res) {
//   const { email } = req.body;

//   try {
//     const [user] = await dbConnection.query(
//       "SELECT * FROM users WHERE email=?",
//       [email]
//     );

//     if (user.length === 0) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "Email not found" });
//     }

//     // Generate a password reset token (20 bytes length)
//     const resetToken = crypto.randomBytes(20).toString("hex");
//     const resetTokenExpiration = Date.now() + 3600000; // 1 hour expiration time

//     // Save the reset token and its expiration in the database
//     await dbConnection.query(
//       "UPDATE users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE email = ?",
//       [resetToken, resetTokenExpiration, email]
//     );

//     // Send reset email with reset link (make sure you have a mailer function to send the email)
//     const resetLink = `http://localhost:5173/reset-password/${resetToken}`;
//     await mailer.sendPasswordResetEmail(email, resetLink);

//     return res
//       .status(StatusCodes.OK)
//       .json({ msg: "Password reset instructions sent to your email" });
//   } catch (error) {
//     console.error("Error during password reset request:", error); // More detailed error logging
//     return res
//       .status(StatusCodes.INTERNAL_SERVER_ERROR)
//       .json({ msg: "Error occurred. Please try again." });
//   }
// }

// // Validate reset token (Step 5: Backend validates the token)
// async function validateResetToken(req, res) {
//   const { token } = req.body;

//   try {
//     // Validate token, check expiration, etc.
//     const [user] = await dbConnection.query(
//       "SELECT * FROM users WHERE resetPasswordToken = ?",
//       [token]
//     );

//     if (!user || user.resetPasswordExpires < Date.now()) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "Invalid or expired token" });
//     }

//     return res.status(StatusCodes.OK).json({ msg: "Valid token" });
//   } catch (error) {
//     console.log(error.message);
//     return res
//       .status(StatusCodes.INTERNAL_SERVER_ERROR)
//       .json({ msg: "Error occurred. Please try again later" });
//   }
// }

// // Password reset (Step 6: Resetting the password with token)
// async function resetPassword(req, res) {
//   const { token, newPassword } = req.body;
//   console.log("Received reset password request with token:", token);

//   try {
//     // Find user by reset token and ensure the token has not expired
//     const [user] = await dbConnection.query(
//       "SELECT * FROM users WHERE resetPasswordToken = ? AND resetPasswordExpires > ?",
//       [token, Date.now()]
//     );

//     if (user.length === 0) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "Invalid or expired token" });
//     }

//     // Hash the new password
//     const hashedPassword = await bcrypt.hash(newPassword, 12);

//     // Update the user's password and clear reset token fields
//     await dbConnection.query(
//       "UPDATE users SET password = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL WHERE email = ?",
//       [hashedPassword, user[0].email]
//     );

//     return res
//       .status(StatusCodes.OK)
//       .json({ msg: "Password has been successfully reset" });
//   } catch (error) {
//     console.error("Error during password reset:", error); // More detailed error logging
//     return res
//       .status(StatusCodes.INTERNAL_SERVER_ERROR)
//       .json({ msg: "Error occurred. Please try again." });
//   }
// }

// module.exports = {
//   register,
//   login,
//   check,
//   requestPasswordReset,
//   resetPassword,
//   validateResetToken, // Added this function to the export
// };

// // Import necessary modules
// const dbConnection = require("../db/dbConfig"); // Database connection
// const bcrypt = require("bcrypt"); // For hashing passwords
// const crypto = require("crypto"); // For generating secure tokens
// const jwt = require("jsonwebtoken"); // For generating JWT tokens
// const { StatusCodes } = require("http-status-codes");
// const mailer = require("../utils/mailer"); // a mailer utility for sending emails

// // Register user
// async function register(req, res) {
//   const { username, firstname, lastname, email, password } = req.body;

//   if (!username || !firstname || !lastname || !email || !password) {
//     return res
//       .status(StatusCodes.BAD_REQUEST)
//       .json({ msg: "please provide all the required informations" });
//   }

//   try {
//     const [user] = await dbConnection.query(
//       "SELECT username, userid FROM users WHERE username=? or email=?",
//       [username, email]
//     );

//     if (user.length > 0) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "username already registered" });
//     }

//     if (password.length < 8) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "password must be at least 8 characters" });
//     }

//     // Encrypt the password
//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(password, salt);

//     await dbConnection.query(
//       "INSERT INTO users (username, firstname, lastname, email, password) VALUES (?,?,?,?,?)",
//       [username, firstname, lastname, email, hashedPassword]
//     );

//     return res.status(StatusCodes.CREATED).json({ msg: "user registered" });
//   } catch (error) {
//     console.log(error.message);
//     return res
//       .status(StatusCodes.INTERNAL_SERVER_ERROR)
//       .json({ msg: "something went wrong, try again later" });
//   }
// }

// // Login user
// async function login(req, res) {
//   const { email, password } = req.body;

//   if (!email || !password) {
//     return res
//       .status(StatusCodes.BAD_REQUEST)
//       .json({ msg: "please provide all the required informations" });
//   }

//   try {
//     const [user] = await dbConnection.query(
//       "SELECT username, userid, password FROM users WHERE email=?",
//       [email]
//     );

//     if (user.length === 0) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "invalid credentials" });
//     }

//     // Compare password
//     const isMatch = await bcrypt.compare(password, user[0].password);

//     if (!isMatch) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "invalid credentials" });
//     }

//     const username = user[0].username;
//     const userid = user[0].userid;
//     const token = jwt.sign({ username, userid }, process.env.JWT_SECRET, {
//       expiresIn: "1d",
//     });

//     return res
//       .status(StatusCodes.OK)
//       .json({ msg: "user login successful", token, username });
//   } catch (error) {
//     console.log(error.message);
//     return res
//       .status(StatusCodes.INTERNAL_SERVER_ERROR)
//       .json({ msg: "something went wrong, try again later" });
//   }
// }

// // Check user (authentication check)
// async function check(req, res) {
//   const username = req.user.username;
//   const userid = req.user.userid;

//   res.status(StatusCodes.OK).json({ msg: "valid user", username, userid });
// }

// // Password reset request (Step 1: Requesting the password reset)
// async function requestPasswordReset(req, res) {
//   const { email } = req.body;

//   try {
//     const [user] = await dbConnection.query(
//       "SELECT * FROM users WHERE email=?",
//       [email]
//     );

//     if (user.length === 0) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "Email not found" });
//     }

//     // Generate a password reset token (20 bytes length)
//     const resetToken = crypto.randomBytes(20).toString("hex");
//     const resetTokenExpiration = Date.now() + 3600000; // 1 hour expiration time

//     // Save the reset token and its expiration in the database
//     await dbConnection.query(
//       "UPDATE users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE email = ?",
//       [resetToken, resetTokenExpiration, email]
//     );

//     // Send reset email with reset link (make sure you have a mailer function to send the email) -- check the frontend here
//     // const resetLink = `http://yourfrontend.com/reset-password/${resetToken}`;
//     const resetLink = `http://localhost:5173/reset-password/${resetToken}`;
//     await mailer.sendPasswordResetEmail(email, resetLink);

//     return res
//       .status(StatusCodes.OK)
//       .json({ msg: "Password reset instructions sent to your email" });
//   } catch (error) {
//     console.log(error.message);
//     return res
//       .status(StatusCodes.INTERNAL_SERVER_ERROR)
//       .json({ msg: "Error occurred. Please try again later" });
//   }
// }

// // Password reset (Step 2: Resetting the password with token)
// async function resetPassword(req, res) {
//   const { token, newPassword } = req.body;
// console.log("Received reset password request with token:", token);
//   try {
//     // Find user by reset token and ensure the token has not expired
//     const [user] = await dbConnection.query(
//       "SELECT * FROM users WHERE resetPasswordToken = ? AND resetPasswordExpires > ?",
//       [token, Date.now()]
//     );

//     if (user.length === 0) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "Invalid or expired token" });
//     }

//     // Hash the new password
//     const hashedPassword = await bcrypt.hash(newPassword, 12); // here for password reset, we can use the same const used above for registration as the two are isolated blocks (different functions or scopes)

//     // Update the user's password and clear reset token fields
//     await dbConnection.query(
//       "UPDATE users SET password = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL WHERE email = ?",
//       [hashedPassword, user[0].email]
//     );

//     return res
//       .status(StatusCodes.OK)
//       .json({ msg: "Password has been successfully reset" });
//   } catch (error) {
//     console.log(error.message);
//     return res
//       .status(StatusCodes.INTERNAL_SERVER_ERROR)
//       .json({ msg: "Error occurred. Please try again later" });
//   }
// }

// module.exports = {
//   register,
//   login,
//   check,
//   requestPasswordReset,
//   resetPassword,
// };

// 1) User Requests Password Reset: The user provides their email to request a reset.
// 2) Backend Sends Email: The backend generates a reset token, stores it temporarily, and sends an email with a link to the frontend. This link points to the frontend's password reset page, where the user can provide a new password.
// 3)User Clicks the Link:The user clicks the link (e.g., http://localhost:5173/reset-password/{resetToken}) in the email.
// 4) Frontend Receives the Token:The frontend reads the reset token from the URL and sends it to the backend for validation.
// 5)Backend Validates Token:The backend checks if the token is valid and hasn’t expired.
// If valid, the frontend displays a form where the user can enter a new password.
// 6) User Submits New Password:The frontend sends the new password to the backend, and the backend updates the user's password in the database.

// The frontend URL is necessary in the backend’s email because the reset link needs to direct the user to the frontend's password reset page. The frontend handles the user interaction of inputting the new password, and the backend validates the reset token and updates the password in the database.

// Without the frontend URL, the user wouldn't know where to go to reset their password. The backend can’t handle user interactions like filling in the new password directly, so it provides a link that directs the user to the frontend route that displays the password reset form.

/********************Initial code *********/

// // db connection
// const dbConection = require("../db/dbConfig");

// // bcrypt to hide our password
// const bcrypt = require("bcrypt");

// //http-status-codes to tell the browser the result of its request.
// const { StatusCodes } = require("http-status-codes");
// const jwt = require("jsonwebtoken");

// async function register(req, res) {
//   const { username, firstname, lastname, email, password } = req.body;

//   if (!username || !firstname || !lastname || !email || !password) {
//     return res
//       .status(StatusCodes.BAD_REQUEST)
//       .json({ msg: "please provide all the required informations" });
//   }

//   try {
//     const [user] = await dbConection.query(
//       "SELECT username,userid FROM users WHERE username=? or email=?",
//       [username, email]
//     );
//     if (user.length > 0) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "username already registered" });
//     }
//     if (password.length < 8) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "passwor must be at least 8 character" });
//     }

//     // encrypt the password
//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(password, salt);

//     await dbConection.query(
//       "INSERT INTO users (username,firstname,lastname,email,password) VALUES (?,?,?,?,?)",
//       [username, firstname, lastname, email, hashedPassword]
//     );

//     return res.status(StatusCodes.CREATED).json({ msg: "user registered" });
//   } catch (error) {
//     console.log(error.message);

//     return res
//       .status(StatusCodes.INTERNAL_SERVER_ERROR)
//       .json({ msg: "something went wrong, try again later" });
//   }
// }

// async function login(req, res) {
//   const { email, password } = req.body;
//   if (!email || !password) {
//     return res
//       .status(StatusCodes.BAD_REQUEST)
//       .json({ msg: "please provide all the required informations" });
//   }

//   try {
//     const [user] = await dbConection.query(
//       "SELECT username,userid,password FROM users WHERE email=?",
//       [email]
//     );

//     if (user.length == 0) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "invalid credential" });
//     }

//     // compare password
//     const isMatch = await bcrypt.compare(password, user[0].password);

//     if (!isMatch) {
//       return res
//         .status(StatusCodes.BAD_REQUEST)
//         .json({ msg: "invalid credential" });
//     }

//     const username = user[0].username;
//     const userid = user[0].userid;
//     const token = jwt.sign({ username, userid }, process.env.JWT_SECRET, {
//       expiresIn: "1d",
//     });
//     return res
//       .status(StatusCodes.OK)
//       .json({ msg: "user login successful", token, username });
//   } catch (error) {
//     console.log(error.message);
//     return res
//       .status(StatusCodes.INTERNAL_SERVER_ERROR)
//       .json({ msg: "something went wrong, try again later" });
//   }
// }

// async function check(req, res) {
//   const username = req.user.username;
//   const userid = req.user.userid;

//   res.status(StatusCodes.OK).json({ msg: "valid user", username, userid });
// }

// module.exports = { register, login, check };
