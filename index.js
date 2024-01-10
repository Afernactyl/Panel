const express = require('express');
const path = require('path');
const session = require('express-session');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
// const name = require('./public/default/assets/img/pageTitle');
const app = express();
const { Theme, pterodactyl } = require('./settings.json');
const routes = require('./routes.json');
const fetch = require('node-fetch');
const axios = require('axios')

// Connect to SQLite database
const db = new sqlite3.Database('data.db');

// Create users table if it doesn't exist

db.serialize(() => {
  // Users table
  db.run('CREATE TABLE IF NOT EXISTS plans (plan_id INTEGER PRIMARY KEY, user_id INTEGER, plan_name TEXT, start_date TEXT, end_date TEXT, FOREIGN KEY (user_id) REFERENCES users(user_id))');
  // AdminSettings table
  db.run('CREATE TABLE IF NOT EXISTS admin_settings (setting_id INTEGER PRIMARY KEY, user_id INTEGER, plans_enabled BOOLEAN DEFAULT 0, FOREIGN KEY (user_id) REFERENCES users(user_id))');
});




app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'public'));

// Serve static files (like stylesheets, images, etc.) from the 'public' folder
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(session({
    secret: 'random',
    resave: false,
    saveUninitialized: true
}));

// Body parser middleware
app.use(bodyParser.urlencoded({ extended: true }));

const isAdmin = (req, res, next) => {
  // Check if the user is an admin, you might want to implement a proper check based on your user model
  const isAdmin = req.user && req.user.isAdmin;

  if (isAdmin) {
      next();
  } else {
      res.status(403).send('Permission Denied');
  }
};

// Save admin settings
app.post('/admin/saveAdminSettings', (req, res) => {
  const { userId, plansEnabled } = req.body;

  // Update the admin_settings table (you would typically update this in a real database)
  db.run('INSERT OR REPLACE INTO admin_settings (user_id, plans_enabled) VALUES (?, ?)', [userId, plansEnabled]);

  res.json({ success: true });
});


// isAuthenticated middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.username) {
    // User is authenticated, fetch user details from the database
    getUserByUsername(req.session.username)
      .then(user => {
        if (user) {
          const isAdmin = user.isAdmin || false;
          req.isAdmin = isAdmin;
          req.user = user;
          next();
        } else {
          res.redirect('/login');
        }
      })
      .catch(error => {
        console.error('Error while fetching user details:', error);
        res.redirect('/login');
      });
  } else {
    // Redirect to login if not authenticated
    res.redirect('/login');
  }
};



async function getPterodactylUserIdByEmail(email) {
  try {
    const response = await fetch(`${pterodactyl.domain}api/application/users`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'Authorization': `Bearer ${pterodactyl.key}`,
      },
    });

    if (response.status === 200) {
      const users = await response.json();
      const user = users.data.find((user) => user.attributes.email === email);

      if (user) {
        return user.attributes.id;
      } else {
        // User not found in the Pterodactyl panel
        console.error('User not found in Pterodactyl panel.');
        return null;
      }
    } else {
      // Handle other API response statuses
      console.error('Error in Pterodactyl panel API:', response.statusText);
      return null;
    }
  } catch (error) {
    // Handle network or other errors
    console.error('Error during Pterodactyl panel API request:', error.message);
    return null;
  }
}

async function getUserByUsername(username) {
  return new Promise((resolve, reject) => {
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
      if (err) {
        reject(err);
      } else {
        resolve(user);
      }
    });
  });
}
async function updatePterodactylUserPassword(userId, newPassword, username, email, password) {
  try {
    // Update the user's password in the Pterodactyl panel


      const response = await fetch(`${pterodactyl.domain}api/application/users/${userId}`, {
      method: 'PATCH',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${pterodactyl.key}`,
      },
      body: JSON.stringify({
        email: email,
        username: username,
        first_name: username,
        last_name: username,
        language: 'en',
        password: newPassword,
      }),
    });

    try {
      const data = await response.json();
      console.log(data);
    } catch (error) {
      console.error(error);
    }

    // Check if the request was successful (status code 200)
    if (response.ok) {
      return true; // Password update in Pterodactyl successful
    } else {
      console.error(`Pterodactyl API error: ${response.statusText}`);
      return false; // Password update in Pterodactyl failed
    }
  } catch (error) {
    console.error('Error updating Pterodactyl user password:', error.message);
    return false; // Password update in Pterodactyl failed
  }
}

async function updateRootAdminStatus(username, rootAdminStatus) {
  return new Promise((resolve, reject) => {
    db.run('UPDATE users SET isAdmin = ? WHERE username = ?', [rootAdminStatus, username], (err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await getUserByUsername(username);

    if (!user || user.password !== password) {
      return res.render(`${Theme.Dashboard_Theme}/login`, { error: 'Invalid username or password. Please try again.' });
    }

    // Check root_admin status using Pterodactyl API
    const pterodactylUserId = await getPterodactylUserIdByEmail(user.email);

    if (pterodactylUserId) {
      const pterodactylUserDetails = await fetch(`${pterodactyl.domain}api/application/users/${pterodactylUserId}`, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'Authorization': `Bearer ${pterodactyl.key}`,
        },
      }).then(response => response.json());

      if (pterodactylUserDetails && pterodactylUserDetails.attributes) {
        const rootAdminStatus = pterodactylUserDetails.attributes.root_admin || false;

        // Update local database with root_admin status
        await updateRootAdminStatus(username, rootAdminStatus);
      }
    }

    req.session.username = username;
    req.user = user; // Set the user object in the request

    res.redirect('/dashboard');
  } catch (error) {
    console.error(error);
    res.render(`${Theme.Dashboard_Theme}/login`, { error: 'Error while authenticating. Please try again.' });
  }
});



// Rest of the code...



app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    // Check if the username already exists in the local database
    const existingUserLocal = await getUserByUsername(username);

    if (existingUserLocal) {
      // Username already exists in the local database, display an error message
      return res.render(`${Theme.Dashboard_Theme}/register`, { error: 'Username already exists. Please choose a different username.' });
    }

    // Check if the username already exists in the Pterodactyl panel API
    const existingUserPanel = await getUserFromPanel(username);

    if (existingUserPanel) {
      // Username already exists in the Pterodactyl panel API, display an error message
      return res.render(`${Theme.Dashboard_Theme}/register`, { error: 'Username already exists. Please choose a different username.' });
    }

    // Username is unique, proceed with registration in both the local database and the Pterodactyl panel API
    await insertUser(username, email, password);
    const panelApiResponse = await createUserInPanel(username, email, password);

    if (panelApiResponse.status === 201) {
      // Registration successful, redirect to the dashboard or another page
      req.session.username = username; // Log in the user automatically after registration
      return res.redirect('/dashboard');
    } else {
      // Error in Pterodactyl panel API, display an error message
      console.error('Error in Pterodactyl panel API:', panelApiResponse.statusText);
      return res.render(`${Theme.Dashboard_Theme}/register`, { error: 'Error during registration. Please try again.' });
    }
  } catch (error) {
    // Handle other errors (e.g., database error)
    console.error('Error during registration:', error);
    return res.render(`${Theme.Dashboard_Theme}/register`, { error: 'Error during registration. Please try again.' });
  }
});

// Helper function to call Pterodactyl panel API and check if the user exists
async function getUserFromPanel(username) {
  const response = await fetch(`${pterodactyl.domain}api/application/users/${username}`, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
      'Authorization': `Bearer ${pterodactyl.key}`,
    },
  });

  if (response.status === 404) {
    // User not found in the Pterodactyl panel API
    return null;
  } else if (response.status === 200) {
    // User found in the Pterodactyl panel API
    return response.json();
  } else {
    // Handle other API response statuses
    throw new Error(`Error in Pterodactyl panel API: ${response.statusText}`);
  }
}


// Helper function to insert user into the database
async function insertUser(username, email, password) {
  return new Promise((resolve, reject) => {
    db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, password], (err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

// Helper function to call Pterodactyl panel API to create a user
async function createUserInPanel(username, email, password) {
  const response = await fetch(`${pterodactyl.domain}api/application/users`, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${pterodactyl.key}`,
    },
    body: JSON.stringify({
      email,
      username,
      first_name: username,
      last_name: username,
      password: password,
    }),
  });
  return response;
}
app.get('/logout', (req, res) => {
  // Destroy the user session
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
    }
    // Redirect the user to the login page after logout
    res.redirect('/login');
  });
});

async function updateUserPassword(username, newPassword) {
  return new Promise((resolve, reject) => {
    db.run('UPDATE users SET password = ? WHERE username = ?', [newPassword, username], (err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

// Add this route handler for changing the login password

app.post('/cpass', isAuthenticated, async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const username = req.session.username;

  try {
    // Fetch the user from the database based on the username
    const user = await getUserByUsername(username);

    if (!user) {
      return res.send('User not found. Please try again.');
    }

    // Check if the provided current password matches the stored password
    if (user.password !== currentPassword) {
      return res.send('Current password is incorrect. Please try again.');
    }

    // Fetch the Pterodactyl user details for the given username
    const pterodactylUserId = await getPterodactylUserIdByEmail(user.email);

    if (!pterodactylUserId) {
      // Pterodactyl user not found, inform the user and stop the process
      return res.send('Pterodactyl user not found. Password not changed.');
    }

    // Update the user's password in the Pterodactyl panel
    const updateResult = await updatePterodactylUserPassword(pterodactylUserId, newPassword, user.username, user.email, user.password);

    if (updateResult) {
      // Update the user's password in the local database
      await updateUserPassword(username, newPassword);

      // Redirect to logout or any other page after successful password change
      res.redirect('/logout');
      return
    } else {
      res.send('Error updating Pterodactyl user password. Please try again.');
    }
  } catch (error) {
    console.error(error);
    res.send('Error while changing password. Please try again.');
  }
});



app.get('/panel', isAuthenticated, async (req, res) => {
  res.redirect(`${pterodactyl.domain}`)
});

async function deleteUser(username) {
  return new Promise((resolve, reject) => {
    db.run('DELETE FROM users WHERE username = ?', [username], (err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

// Helper function to call Pterodactyl panel API and delete a user by ID
async function deleteUserFromPanel(userId) {
  try {
    const response = await fetch(`${pterodactyl.domain}api/application/users/${userId}`, {
      method: 'DELETE',
      headers: {
        'Accept': 'application/json',
        'Authorization': `Bearer ${pterodactyl.key}`,
      },
    });

    if (response.status === 204) {
      // User successfully deleted from the Pterodactyl panel
      return true;
    } else {
      // Handle other API response statuses
      console.error('Error in Pterodactyl panel API:', response.statusText);
      return false;
    }
  } catch (error) {
    // Handle network or other errors
    console.error('Error during Pterodactyl panel API request:', error.message);
    return false;
  }
}

// Updated /da route
app.post('/da', isAuthenticated, async (req, res) => {
  const username = req.session.username;
  const { password } = req.body;

  try {
    // Fetch the user from the database based on the username
    const user = await getUserByUsername(username);

    if (!user) {
      return res.send('User not found. Please try again.');
    }

    // Check if the provided password matches the stored password
    if (user.password !== password) {
      return res.send('Incorrect password. Please try again.');
    }

    // Fetch the Pterodactyl user ID for the given email
    const pterodactylUserId = await getPterodactylUserIdByEmail(user.email);

    if (!pterodactylUserId) {
      // Pterodactyl user not found, proceed with local database deletion
      await deleteUser(username);

      // Destroy the user session
      req.session.destroy((err) => {
        if (err) {
          console.error(err);
        }
        res.redirect('/login'); // Redirect to the login page after successful deletion
      });
    } else {
      // Delete the user from the Pterodactyl panel
      const panelDeleteSuccess = await deleteUserFromPanel(pterodactylUserId);

      if (panelDeleteSuccess) {
        // User successfully deleted from the Pterodactyl panel, now delete from the local database

        // Delete the user from the local database
        await deleteUser(username);

        // Destroy the user session
        req.session.destroy((err) => {
          if (err) {
            console.error(err);
          }
          res.redirect('/login'); // Redirect to the login page after successful deletion
        });
      } else {
        // Error during Pterodactyl panel API call, display an error message
        res.send('Error during account deletion. Please try again.');
      }
    }
  } catch (error) {
    console.error(error);
    res.send('Error during account deletion. Please try again.');
  }
});



async function fetchVersionFromAPI() {
  try {
    const response = await axios.get('http://103.178.158.190:1447/');
    const apiVersion = response.data.version;
    return { apiVersion };
  } catch (error) {
    console.error('Error fetching version from API:', error.message);
    throw error;
  }
}

async function renderVersionPage(req, res) {
  try {
    const { apiVersion } = await fetchVersionFromAPI();
    const localVersion = Theme.version;  // Assuming Theme.version contains your local version

    res.render(`${Theme.Dashboard_Theme}/version`, {
      pageTitle: 'Software Version',
      isAdmin: req.isAdmin,
      username: req.session.username,
      version: { localVersion: localVersion, apiVersion: apiVersion },  // Pass localVersion
      downloadLink: 'http://yourdownloadlink.com',
    });
  } catch (error) {
    console.error('Error rendering version page:', error.message);
    res.status(500).send('Error rendering version page');
  }
}



// Function to get all users from the database
const getAllUsers = () => {
  return new Promise((resolve, reject) => {
      db.all('SELECT * FROM users', (err, rows) => {
          if (err) {
              reject(err);
          } else {
              resolve(rows);
          }
      });
  });
};

// Set a global variable for the template
app.use((req, res, next) => {
  res.locals.username = req.session.username;
  next();
});

const arePlansEnabled = async () => {
  return new Promise((resolve, reject) => {
    // Assuming your database query logic here to fetch the plansEnabled status
    db.get('SELECT plans_enabled FROM admin_settings WHERE user_id = ?', [/* your user_id logic here */], (err, row) => {
      if (err) {
        reject(err);
      } else {
        // Check if the row exists and plans are enabled
        const plansEnabled = row && row.plans_enabled === 1;
        resolve(plansEnabled);
      }
    });
  });
};


Object.keys(routes).forEach(routeKey => {
  const route = routes[routeKey];
  const routeHandler = [];

  // Check for authentication
  if (route.requiredAuth) {
    routeHandler.push(isAuthenticated);
  }

  // Check for admin access
  if (route.isAdmin) {
    routeHandler.push(isAdmin);
  }

  app.get(route.url, ...routeHandler, async (req, res) => {
    try {
      // Fetch all users from the database
      const users = await getAllUsers();
      // const version = await fetchVersionFromAPI();
      const plansEnabled = await arePlansEnabled();
      // Now req.isAdmin is available here
      res.render(`${Theme.Dashboard_Theme}/${routeKey}`, {
        pageTitle: route.pageTitle,
        isAdmin: req.isAdmin,
        username: req.session.username,
        users: users,
        // version: { localVersion: Theme.version, apiVersion: version.apiVersion },
        plansEnabled: plansEnabled,
        downloadLink: 'http://afernactyl.leoxstudios.com/downloadupdate',
      });
    } catch (error) {
      console.error(error);
      res.status(500).send('Error fetching users');
    }
  });
});

app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
  res.redirect('/admin/home')
})

// 404 route
app.use((req, res) => {
  res.status(404).render(`${Theme.Dashboard_Theme}/404.ejs`, { pageTitle: 'Page Not Found' });
});
// Start the server
app.listen(Theme.port, () => {console.log('Started!')});