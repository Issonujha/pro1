require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
// const md5 = require('md5'); //for Hash Password
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
const exphbs = require('express-handlebars');
const findOrCreate = require('mongoose-findorcreate');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const session = require("express-session");
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');



//when we use cypher text password to be store in database
// const encrypt = require("mongoose-encryption");

const app = express();

console.log(process.env.API_KEY);

app.use(express.static("public"));

app.set('view engine', 'ejs');
// app.engine('handlebars', exphbs());
// app.set('view engine', 'handlebars');

app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    fbID: String,
    secret: String
});


userSchema.plugin(passportLocalMongoose);
//Cypher text parssword with encrytion
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
})

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function(accessToken, refressToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({ googleId : profile.id }, function(err, user) {
            return cb(err, user);
        });
    }
));

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FB_ID,
      clientSecret: process.env.FB_SECRET,
      callbackURL: "http://localhost:3000/auth/facebook/secrets",
      userProfileURL: "https://www.facebookapis.com/oauth2/v3/userinfo"
    },
    function(accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ fbID : profile.id }, function(err, user) {
            return cb(err, user);
        });
    }
  )
);

app.get("/", function(req, res) {
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/facebook", 
    passport.authenticate('facebook')
);

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: "/login" }),
    function(req, res) {
        res.redirect("/secrets");
    }
);

app.get(
  "/auth/facebook/secrets",
  passport.authenticate('facebook', { failureRedirect: "/login" }),
  function(req, res) {
    // console.log("req", req.user)
    res.redirect("/secrets");
  }
)

app.get("/login", function(req, res) {
    if(req.isAuthenticated()) {
        res.redirect("secrets");
    }
    else {
        res.render("login");
    }
});

app.get("/register", function(req, res) {
    res.render("register");
});


app.get("/secrets", function(req, res) {
    User.find({"secret": {$ne: null}}, function(err, users) {
        if(err) {
            console.log(err);
        }
        else {
            res.render("secrets", {userWithSecrets: users});
        }
    });
});

app.get("/submit", function(req, res) {
    if(req.isAuthenticated()) {
        res.render("submit");
    }
    else {
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res) {
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, function(err, user) {
        if(err) {
            console.log(err);
        }
        else {
            if(user) {
                user.secret = submittedSecret;
                user.save();
                res.redirect("/secrets");
            }
        }
    });
});

app.post('/register', function(req, res) {

    // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash
    //     });
    //     newUser.save(function(err) {
    //         if(err) {
    //             console.log(err);
    //         }
    //         else {
    //             res.render("secrets");
    //         }
    //     });
    // });

    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if(err) {
            console.log(err);
            res.redirect("/register");
        }
        else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            })
        }
    })

});

app.post('/login', function(req, res) {
    // const username = req.body.username;
    // // const password = md5(req.body.password);
    // const password = req.body.password;


    // User.findOne({ email: username}, function(err, user) {
    //     if(err) {
    //         console.log(err);
    //     }
    //     else {
    //         if(user) {
    //             bcrypt.compare(password, user.password, function(err, result) {
    //                 // console.log(user.password);
    //                 if(result === true) {
    //                     res.render("secrets");
    //                 }
    //             });
    //         }
    //     }
    // });
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });

        req.login(user, function(err) {
            if(err) {
                console.log(err);
            }
            else {
                passport.authenticate("local")(req, res, function(){
                    res.redirect("/secrets");
                });
            }
        });
});

app.get("/logout", function(req, res) {
    req.logout(function(err) {
    if (err) { 
        console.log(err); 
    }
    else {
        res.redirect("/");
    }
    });
});


app.listen(3000, function() {
    console.log('listening on port 3000');
});