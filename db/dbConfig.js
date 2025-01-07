/** @format */

const mysql2 = require("mysql2");

// const dbConnection = mysql2.createPool({
//   user: process.env.USER,
//   database: process.env.DATABASE,
//   host: "localhost",
//   password: process.env.PASSWORD,
//   connectionLimit: 10,
// });


const dbConnection = mysql2.createPool({
  user: process.env.USER,
  database: process.env.DATABASE,
  host: process.env.HOST,
  password: process.env.PASSWORD,
  // port: process.env.PORT,  // port to connect backend to the MySQL database; mine : this is default for mySQl and may need to be commented out ; deployment to render failed cause searching for this open port timed out 
  connectionLimit: 10,
});

module.exports = dbConnection.promise();



