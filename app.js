const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const path = require('path');
const mysql = require('mysql2');

// MySQL Connection
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Thrinesh@0405',
  database: 'se'
});

connection.connect(err => {
  if (err) throw err;
  console.log('Connected to the MySQL server.');
  createDefaultAdmin(); // Call the function here
});

const app = express();

// Set up view engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
// Middleware
app.use(bodyParser.json());
app.use(session({ secret: 'your_secret_key', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

const flash = require('connect-flash');
app.use(flash());
app.use(express.json());

app.use('/fa', express.static(__dirname + '/node_modules/font-awesome/css'));
app.use('/fonts', express.static(__dirname + '/node_modules/font-awesome/fonts'));

// Passport Local Strategies
passport.use('local-login', new LocalStrategy({
  usernameField: 'user_name',
  passwordField: 'password'
}, (username, password, done) => {
  connection.query('SELECT * FROM users WHERE user_name = ?', [username], (err, results) => {
    if (err) return done(err);

    if (!results.length) return done(null, false, { message: 'Incorrect username.' });

    const user = results[0];
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) return done(err);

      if (!isMatch) return done(null, false, { message: 'Incorrect password.' });

      return done(null, user);
    });
  });
}));


function createDefaultAdmin() {
  const defaultAdmin = {
    first_name: 'Default',
    last_name: 'Admin',
    mob_no: '0000000000',
    user_name: 'admin',
    password: 'admin123',
    email: 'admin@example.com',
    role: 'admin',
  };

  connection.query('SELECT * FROM users WHERE role = ?', ['admin'], (err, results) => {
    if (err) {
      console.error('Error checking for admin users:', err);
      return;
    }

    if (results.length === 0) {
      bcrypt.hash(defaultAdmin.password, 10, (err, hashedPassword) => {
        if (err) {
          console.error('Error hashing default admin password:', err);
          return;
        }

        defaultAdmin.password = hashedPassword;

        connection.query('INSERT INTO users SET ?', defaultAdmin, (err, results) => {
          if (err) {
            console.error('Error creating default admin:', err);
            return;
          }

          console.log('Default admin created successfully');
        });
      });
    } else {
      console.log('Admin users already exist');
    }
  });
}


function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.role === 'admin') {
    return next();
  }
  res.redirect('/');
}


app.post('/login',
  passport.authenticate('local-login', {
    successRedirect: '/welcome',
    failureRedirect: '/',
    failureFlash: 'Invalid username or password'
  })
);

passport.use('local-signup', new LocalStrategy({
  usernameField: 'user_name',
  passwordField: 'password',
  passReqToCallback: true,
}, (req, username, password, done) => {
  debugger;
  console.log(req, 'req');
  console.debug(username, 'username');
  console.debug(req.body.email, 'email');
  connection.query('SELECT * FROM users WHERE user_name = ? OR email = ?', [username, req.body.email], (err, results) => {
    if (err) return done(err);

    if (results.length > 0) {
      
      return done(err, true, {message: 'User already registered'});
    } else {
    bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return done(err);

    const newUser = {
      first_name: req.body.first_name,
      last_name: req.body.last_name,
      mob_no: req.body.mob_no,
      user_name: username,
      password: hashedPassword,
      email: req.body.email,
      role: req.body.role
    };

    connection.query('INSERT INTO users SET ?', newUser , (err, results) => {

      if (err)return done(err);
        
      newUser.id = results.insertId;
      return done(null, newUser);
    });
  });
}
});
}));


passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  connection.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
    if (err) return done(err);

    done(null, results[0]);
  });
});

// Routes
app.get('/', (req, res) => {
  res.render('login', { message: req.flash('error') || '' });
});



app.get('/login', function(req, res) {
  res.render('login', { message: req.flash('error') || '' });
});

app.get('/forgot-password', function(req, res) {
  res.render('forgot-password');
});

app.get('/signup', (req, res) => {
  res.render('signup');
});

app.post('/signup', (req, res, next) => {
  console.debug(req,'req1');
  passport.authenticate('local-signup', (err, user, info) => {
    if(user && info && info.message) {
      // return res.status(200).json({ success: false, message: info.message });
      return res.redirect('/signup?userRegistered=true');
    }

    if (err) {     req.flash('error', 'An error occurred while registering the user');
    return res.redirect('/signup');
    }

    if (!user) {
      req.flash('error', 'Failed to register user');
      return res.redirect('/signup');
    }

    req.flash('success', 'User registered successfully');
    res.redirect('/');

  })(req, res, next);
});

app.post('/login', passport.authenticate('local-login', {
  successRedirect: '/welcome',
  failureRedirect: '/',
  failureFlash: 'Invalid username or password'
}));
app.post('/forgot-password', function(req, res) {
  // Code to send password reset link to the user's email
});
app.get('/welcome', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');

  if (req.user.role === 'admin') {
    connection.query('SELECT * FROM users', (err, users) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Error fetching users');
      }

      // Fetch emission_values from the database
      connection.query('SELECT * FROM emission_values', (error, emissionValues) => {
        if (error) {
          console.error('Error fetching emission_values:', error);
          return res.status(500).send('Error fetching emission values');
        }

        // Pass both users and emissionValues to the view
        res.render('admin-welcome', {
          user: req.user,
          users: users,
          emissionValues: emissionValues,
          success: req.query.success, 
          error: req.query.error,
        });
      });
    });
  } else if (req.user.role === 'user') {
    res.render('user-welcome', { user: req.user });
  } else {
    res.redirect('/');
  }
});



  app.post('/admin-actions/change-role', (req, res) => {
    if (!req.isAuthenticated() || req.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    const { userId, newRole } = req.body;

    if (userId == req.user.id) {
        return res.status(400).json({ success: false, message: 'Admin cannot change their own role' });
    }

    connection.query(
        'UPDATE users SET role = ? WHERE id = ?',
        [newRole, userId],
        (err, results) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ success: false, message: 'Error updating user role' });
            }

            if (results.affectedRows === 0) {
                return res.status(404).json({ success: false, message: 'User not found' });
            }

            res.status(200).json({ success: true, message: 'User role updated successfully' });
        }
    );
});

app.post('/admin-actions/delete-user', (req, res) => {
    if (!req.isAuthenticated() || req.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    const { userId } = req.body;

    if (userId == req.user.id) {
        return res.status(400).json({ success: false, message: 'You cannot delete your own account' });
    }

    connection.query('DELETE FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: 'Error deleting user' });
        }

        if (results.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        res.status(200).json({ success: true, message: 'User has been deleted' });
    });
});

  






app.get("/user-weather", ensureUserOrAdmin, (req, res) => {
    res.render("user-weather", { user: req.user });
  });
  
  app.get("/user-welcome", ensureUserOrAdmin, (req, res) => {
    res.render("user-welcome", { user: req.user });
  });
  
  




  function ensureUserOrAdmin(req, res, next) {
    if (req.isAuthenticated()) {
      if (req.user.role === "user" || req.user.role === "admin") {
        return next();
      } else {
        req.flash("error_msg", "You do not have permission to view this page.");
        res.redirect("/login");
      }
    } else {
      req.flash("error_msg", "Please log in to view this page.");
      res.redirect("/login");
    }
  }
  



  app.get('/search-history', (req, res) => {
    if (!req.isAuthenticated() || !(req.user.role === 'user' || req.user.role === 'admin')) {
      return res.redirect('/');
    }
    const userId = req.user.id;
    connection.query('SELECT * FROM search_history WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Error fetching search history');
      }
      res.render('search-history', { history: results, user: req.user });
    });
  });
  
  app.post('/api/search-history', (req, res) => {
    if (!req.isAuthenticated() || !(req.user.role === 'user' || req.user.role === 'admin')) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
  
    const userId = req.user.id;
    const { origin, destination, mode, distance, duration, emissions, caloriesBurned } = req.body;
  
    const searchHistoryData = {
        user_id: userId,
        origin,
        destination,
        mode,
        distance,
        duration,
        emissions: parseFloat(emissions),
        calories_burned: parseFloat(caloriesBurned),
      };
  
    connection.query('INSERT INTO search_history SET ?', searchHistoryData, (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: 'Error saving search history' });
      }
  
      res.status(200).json({ success: true, message: 'Search history saved successfully' });
    });
  });
    


  app.get('/api/emission-values', ensureAdmin, (req, res) => {
    connection.query('SELECT * FROM emission_values', (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: 'Error fetching emission values' });
      }
      res.status(200).json({ success: true, data: results });
    });
  });

  app.post('/update-emission-value/:id', ensureAdmin, (req, res) => {
    const id = req.params.id;
    const emissionsPerMeter = req.body.emissions_per_meter;
  
    connection.query('UPDATE emission_values SET emissions_per_meter = ? WHERE id = ?', [emissionsPerMeter, id], (error, results) => {
      if (error) {
        console.error('Error updating emission_values:', error);
        res.status(500).json({ success: false, message: 'Update failed' });
        return;
      }
  
      res.status(200).json({ success: true, message: 'Update successful' });
    });
  });

  
 
  

  


app.get('/logout', (req, res) => {
    req.session.destroy(err => {
      if (err) {
        console.error(err);
        return res.status(500).send('Error logging out');
      }
      res.redirect('/');
    });
  });
  

app.listen(4000, () => {
  console.log('Server started on port 4000');
});
