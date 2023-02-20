const db = require("../../interfaces/index");
const User = db.users;
const encr = require('../../middleware/encrypt')
const { comparePassword, verifyEmail, checkUnique } = require('../../middleware/verify')
const jwt = require('jsonwebtoken');

const requiredFields = [
    'first_name',
    'last_name',
    'password',
    'email'
]

exports.signUp = async (req, res) => {
    let incoming = {first_name: req.body.first_name,last_name: req.body.last_name,email: req.body.email,password: encr.encrypt(req.body.password)};
    try {
        if (Object.values(incoming).some(x => x == '')) {
            res.status(400).json({
                message: "A required field is missing."
            });
        } 

        const saved = await User.create(incoming);
        const access_token = jwt.sign({ id: saved.id }, process.env.JWT_SEC, {
            expiresIn: 86400
        })

        res.status(200).json({access_token})
    } catch (err) {
        if(!verifyEmail(incoming.email)){
            res.status(400).json({
                message: "Email is invalid"
            });
        } else if(await checkUnique(incoming.email) == true){
            res.status(400).send({
                message: err.errors[0].message
            });
        } else {
            res.status(500).send({
                message: Error
            });
        }
    }
    
}

exports.login = async (req, res) => {
    const user = await User.findOne({ where:{ email: req.body.email }});
    const password = await comparePassword(req.body.password, user.password)

    if(!user || !req.body.password || !password) res.status(401).json({
        message: "The username or password are incorrect. Please try again, or contact the site admin."
    })

    const token = jwt.sign({ id: user.id }, process.env.JWT_SEC, {
        expiresIn: 86400
    })

    return res.json({
        id: user.id,
        name: user.name,
        token: token
    })
}

exports.refresh = async (req, res) => {
    
}