const nodemailer = require("nodemailer");

// Create a reusable transporter object using SMTP transport
const transporter = nodemailer.createTransport({
  service: "gmail", // Using Gmail as the email service
  auth: {
    user: process.env.EMAIL_USER, // Your Gmail address (from .env)
    pass: process.env.EMAIL_PASSWORD, // The App Password you generated (from .env)
  },
});

// Function to send the password reset email
const sendPasswordResetEmail = async (email, resetLink) => {
  const mailOptions = {
    from: process.env.EMAIL_USER, // Sender's email address
    to: email, // Receiver's email address
    subject: "Password Reset Request",
    html: `<p>We received a request to reset your password. Click the link below to reset your password:</p>
           <p><a href="${resetLink}">${resetLink}</a></p>
           <p>This reset password link will be valid only for 1 hour. If you did not request this, please ignore this email.</p>`,
  };

  try {
    await transporter.sendMail(mailOptions); // Send the email
    console.log("Password reset email sent successfully");
  } catch (error) {
    console.error("Error sending password reset email:", error); // Detailed error logging
    throw new Error("Failed to send password reset email");
  }
};

module.exports = { sendPasswordResetEmail };
