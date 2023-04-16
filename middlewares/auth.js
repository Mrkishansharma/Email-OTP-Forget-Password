
const jwt = require('jsonwebtoken')

require('dotenv').config()

const { blacklistedUser } = require('../blacklisted')


const Auth = async (req, res, next) => {

    const { token } = req.cookies;

    if (token) {

        console.log(blacklistedUser, token);

        if (blacklistedUser.includes(token)) {

            return res.status(400).send({

                "msg": "Login Required....!!"

            })
        }

        try {

            const decoded = jwt.verify(token, process.env.accessToken);

            if (decoded) {

                req.body.UserID = decoded.UserID;

                next()

            }

        } catch (error) {

            return res.status(403).send({
                "msg": "Authorization Failed.Login required.",
                error:error.message
            });

        }

    } else {

        res.status(400).send({
            "msg": "Kindly Login First"
        });

    }
}





module.exports = {
    Auth
}


