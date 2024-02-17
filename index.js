const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const saltRounds = 10;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
// MySQL Connection

const connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: '',
    database: ''
});

connection.connect((err) => {
  if (err) throw err;
  console.log('Connected to MySQL database');
});

// Secret key for JWT
const secretKey = 'myauthsecret';
app.get('/', (req, res) => {
    res.render('index');
  });
  
  // Registration form
  app.get('/register', (req, res) => {
    res.render('register');
  });
  
  // Register user
  app.post('/register', (req, res) => {
    const { name, email, password,image } = req.body;
    image
    bcrypt.hash(password, saltRounds, (err, hash) => {
      if (err) throw err;
  
      const user = { name, email, password: hash,image };
  
      connection.query('INSERT INTO users SET ?', user, (err, result) => {
        if (err) throw err;
        res.redirect('/login');
      });
    });
  });
  
  // Login form
  app.get('/login', (req, res) => {
    res.render('login');
  });
  
  // Login user
  app.post('/login', (req, res) => {
    const { email, password } = req.body;
  
    connection.query(
      'SELECT * FROM users WHERE email = ?',
      [email],
      (err, results) => {
        if (err) throw err;
  
        if (results.length > 0) {
          const user = results[0];
  
          bcrypt.compare(password, user.password, (err, result) => {
            if (err) throw err;
  
            if (result) {
              const token = jwt.sign({ id: user.id }, secretKey, {
                expiresIn: '1h',
              });
              res.cookie('token', token);
              res.redirect('/home');
            } else {
              res.redirect('/login');
            }
          });
        } else {
          res.redirect('/login');
        }
      }
    );
  });
  
  // Home page for authenticated users
  app.get('/home', authenticateToken, (req, res) => {
    const userId = req.user.id;
  console.log("/home",userId)
    connection.query(
      'SELECT * FROM users WHERE id = ?',
      [userId],
      (err, results) => {
        if (err) throw err;
     console.log("result",results)
        if (results.length > 0) {
          const user = results[0];
          console.log(user)
          res.render('home', { user:user });
        } else {
          res.redirect('/login');
        }
      }
    );
  });
  
  // Middleware to authenticate token
  function authenticateToken(req, res, next) {
    try{

   
      const token = req.cookies.token;
    // console.log("authheader",authHeader)

  
    if (!token) {
      return res.redirect('/login');
    }
  
    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        return res.redirect('/login');
      }
      req.user = decoded;
      next();
    });


    }
    catch(err){
      console.log(err)
    }
  }
  
  const port = 3000;
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });