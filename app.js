require("dotenv").config();
const express = require("express");
const app = express();
const port = process.env.PORT || 5500 ; //DKG: port where backend listens requests coming from frontend ; process.env.PORT added for render deployment to work; When deploying on Render, the environment variable PORT is automatically set for you by the platform, and this is the port that your app should listen to. Therefore, you should not set PORT manually in .env for Render deployments. For local development, the fallback (5500) ensures that your app will still work without issues, but Render will use process.env.PORT for the production environment.
const cors = require("cors");

app.use(cors());

// const corsOptions = {
//   origin: "http://localhost:5173", // Your frontend URL
//   methods: ["GET", "POST", "PUT", "DELETE"],
//   credentials: true, // Allow credentials if needed (cookies, etc.)
// };

// app.use(cors(corsOptions));


// db connection
const dbConection = require("./db/dbConfig");

// authentication middleware
const authMiddleware = require("./middleware/authMiddleware");

// user router middleware file
const userRouter = require("./routes/userRoute");
// json middleware to extract json data
app.use(express.json());

//get request  ; added to get a success message when deploying it on render
app.get("/", (req, res) => {
  res.status(200).json({
    message: "Success!",
  });
});

// user router middleware
app.use("/api/users", userRouter);

// question router middleware file
const questionRoute = require("./routes/questionRoute");
// question router middleware
app.use("/api/questions", authMiddleware, questionRoute);

// answer router middleware file
const answerRoute = require("./routes/answerRoute");
// answer router middleware
app.use("/api", authMiddleware, answerRoute);

async function start() {
  try {
    const result = await dbConection.execute("select 'test'");
    await app.listen(port);
    console.log("database connection established");
    console.log(`listening on ${port}`);
  } catch (error) {
    console.log(error.message);
  }
}
start();
