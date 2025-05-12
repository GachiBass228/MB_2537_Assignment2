require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = 60 * 60 * 1000; //expires after 1 hour  (minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage");
        return;
    }
    else {
        next();
    }
}

app.get('/', async (req,res) => {
    if (!req.session.authenticated) {
    /*    const html = `
        <form action='/createUser' method='get'>
            <button>Sign up</button>
        </form>
        <form action='/login' method='get'>
            <button>Log in</button>
        </form>
    `;
        res.send(html);*/
        res.render("index");
    } else {
        res.render("loggedin", {users: req.session.username});
    }
});

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: "+email);
    }
});


app.get('/createUser', (req,res) => {
    /*var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);*/
    res.render("signup");
});


app.get('/login', (req,res) => {
    /*var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);*/
    res.render("login");
});

app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var email = req.body.email
    var password = req.body.password;

	const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().max(20).required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({username, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/createUser");
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, email: email, password: hashedPassword, user_type:"user"});
	console.log("Inserted user");
    req.session.authenticated = true;
    req.session.username = username;
    req.session.user_type = "user";
	req.session.cookie.maxAge = expireTime;
    res.redirect('/membersPage');
});

app.post('/loggingin', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, user_type: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length !== 1) {
		console.log("Incorrect username/password");
        var html = `
            <h3>incorrect username/password</h3>
            <a href='/login'>Try again</a>
        `;
        res.send(html);
        return;
	}

    const userMatch = result[0];
    const passwordMatch = await bcrypt.compare(password, result[0].password);

	if (userMatch && passwordMatch) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.username = username;
        req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/loggedIn');
		return;
	}
    else{ 

        var html = `
            <h3>incorrect password</h3>
            <a href='/login'>Try again</a>
        `;
        res.send(html);
		//console.log("incorrect password");
		//res.redirect("/login");
		return;
	}
});

app.get('/loggedIn', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    else{
        res.redirect('/membersPage');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Error logging out');
        }
        res.redirect('/');
    });
});


app.get('/membersPage', (req,res) => {

    if (req.session.authenticated){
   /* const images = ["/cat1.jpg", "/cat2.jpg", "/cat3.jpg"];
    const randomIndex = Math.floor(Math.random() * images.length);
    const selectedImage = images[randomIndex];

    var html = `
        <h3>Hello, ${req.session.username}.</h3>
        <img src='${selectedImage}' style='width:250px;'>
        <form action='/logout' method='get'>
        <button>Logout</button>
        </form>
    `;
    res.send(html);*/
    res.render("cats");
    
    }
    else{
        res.redirect('/');
    }
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection.find().project({username: 1, user_type: 1, _id: 1}).toArray();
 
    res.render("admin", {users: result});
});

// Promote user to admin
app.get('/promote/:id', sessionValidation, adminAuthorization, async (req, res) => {
    try {
      const userId = new ObjectId(req.params.id);
      await userCollection.updateOne({ _id: userId }, { $set: { user_type: 'admin' } });
      res.redirect('/admin');
    } catch (error) {
      console.error('Error promoting user:', error);
      res.status(500).render('500', { title: 'Server Error' });
    }
  });
  
  // Demote admin to regular user
app.get('/demote/:id', sessionValidation, adminAuthorization, async (req, res) => {
    try {
      const userId = new ObjectId(req.params.id);
      await userCollection.updateOne({ _id: userId }, { $set: { user_type: 'user' } });
      res.redirect('/admin');
    } catch (error) {
      console.error('Error demoting user:', error);
      res.status(500).render('500', { title: 'Server Error' });
    }
  });
 

app.use(express.static(__dirname + "/public"));

app.use(function (req, res) {
    res.status(404);
    res.render('404');
});

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 