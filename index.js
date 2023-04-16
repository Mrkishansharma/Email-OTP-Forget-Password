const express = require('express');

const app = express();

require('dotenv').config();

const session = require('express-session')

const cookieParser = require('cookie-parser');

const nodemailer = require('nodemailer');


const bcrypt = require('bcrypt');

const jwt = require('jsonwebtoken');

const { UserModel } = require('./models/user.model');

const { connection } = require('./db');

const { Auth } = require('./middlewares/auth');

const { blacklistedUser } = require('./blacklisted')


app.use(express.json());

app.use(cookieParser());

// express-session - middlewares
app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true
}))



// create reusable transporter object using the default SMTP transport
let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'sharmakishan.7718@gmail.com',
        pass: process.env.PASS_CODE
    }
});



function generateOTP() {
    let otp = ''
    for (let i = 0; i < 4; i++) {
        otp += Math.floor(Math.random() * 10)
    }
    return otp
}

app.get('/send-otp', (req, res) => {

    const { Email } = req.body;

    const otp = generateOTP();

    console.log(otp);

    // setup email data
    let mailOptions = {
        from: 'sharmakishan.7718@gmail.com',
        to: Email,
        subject: '<Important Read Required> Your Verification OTP',
        text: `Thanks for joining us. Your OTP is ${otp}`
    };

    // send email
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
            res.send('Error sending email');
        } else {
            console.log('Email sent: ' + info.response);

            req.session.OTP = otp;

            res.send('Email sent successfully');
        }
    });
});


app.get('/register', async (req, res) => {

    const { otp } = req.query;

    const serverOTP = req.session.OTP;

    console.log(otp, serverOTP);

    if (serverOTP === otp) {
        // res.send('otp is verified')
        register(req, res)
    } else {
        res.send('kya kar rha hai bhai. ye sab doglapan nhi chalega')
    }

})






async function register(req, res) {

    const { Email, Name, Password } = req.body;

    if (!Email || !Name || !Password) {

        return res.status(400).send({
            "msg": "Please provide all details"
        });

    }




    try {

        const isVerify = await UserModel.aggregate([{ $match: { Email: Email } }])

        if (isVerify.length) {

            return res.status(400).send({
                "error": "User Already exists."
            });

        }


        bcrypt.hash(Password, 5, async (err, hash) => {

            if (err) {

                return res.status(400).send({
                    "msg": "Something went wrong"
                });

            }

            const user = new UserModel({ Email, Password: hash, Name });

            await user.save();

            return res.status(200).send({
                "msg": "New user registration Successfully done.",
                "User": user
            });

        })

    } catch (error) {

        return res.status(400).send({
            "error": error.message
        });

    }



}




app.post("/login", async (req, res) => {

    const { Email, Password } = req.body;

    try {

        const verifyuser = await UserModel.aggregate([{ $match: { Email: Email } }])


        if (verifyuser.length == 0) {

            return res.status(404).send({
                "msg": "User doesn't exists."
            });

        }


        bcrypt.compare(Password, verifyuser[0].Password, async (err, result) => {
            console.log(err)
            console.log(result)
            if (!result) {

                return res.status(400).send({
                    "msg": "Invalid Password!"
                });

            }

            const token = jwt.sign({ UserID: verifyuser[0]._id }, process.env.accessToken, { expiresIn: '5m' });

            res.cookie('token', token, { maxAge: 1000 * 60 * 5 });

            const response = {
                "msg": "Login Successfull"
            }

            return res.status(200).send(response);

        })


    } catch (error) {

        return res.status(400).send({
            "error": error.message
        });

    }

})


app.get('/logout', (req, res) => {

    const { token } = req.cookies;

    blacklistedUser.push(token);

    res.send({ msg: "Logout Successfull." })

})


app.patch('/forget-pass', async (req, res) => {

    const { otp } = req.query || req.body;

    const { Email, Password } = req.body;

    const serverOTP = req.session.OTP;

    console.log(otp, serverOTP);

    if (serverOTP === otp) {


        if (!Email || !Password) {

            return res.status(400).send({
                "msg": "Please provide all details"
            });

        }




        try {

            const isVerify = await UserModel.aggregate([{ $match: { Email: Email } }])

            if (!isVerify.length) {

                return res.status(400).send({
                    "error": "User Does not exists."
                });

            }


            bcrypt.hash(Password, 5, async (err, hash) => {

                if (err) {

                    return res.status(400).send({
                        "msg": "Something went wrong"
                    });

                }

                await UserModel.findOneAndUpdate({ Email }, { Password:hash })

                res.send({ msg: "Password Successfully updated" })
            })

        } catch (error) {

            return res.status(400).send({
                "error": error.message
            });

        }

    } else {

        res.send({ msg: 'OTP Invalid' });

    }
})


// Protected Routes - login required
app.get('/reports', Auth, (req, res) => {
    res.send("Reports")
})




app.listen(process.env.port, async () => {

    try {

        await connection;

        console.log('mongo connected');

    }

    catch (error) {

        console.log(error);

    }

    console.log("server is runnning..");
})


