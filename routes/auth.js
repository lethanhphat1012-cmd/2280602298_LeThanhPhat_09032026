var express = require('express');
var router = express.Router();
let userController = require('../controllers/users');
let jwt = require('jsonwebtoken')
let { checkLogin } = require('../utils/authHandler.js')
const bcrypt = require("bcryptjs");
const User = require("../schemas/users");

router.post('/register', async function (req, res) {

    let newUser = await userController.CreateAnUser(
        req.body.username,
        req.body.password,
        req.body.email,
        "69a5462f086d74c9e772b804"
    )

    res.send({
        message: "dang ki thanh cong"
    })

});

router.post('/login', async function (req, res) {

    let result = await userController.QueryByUserNameAndPassword(
        req.body.username,
        req.body.password
    )

    let token = jwt.sign(
        { id: result.id },
        'secret',
        { expiresIn: '1h' }
    )

    res.send(token)

});

router.get('/me', checkLogin, async function (req, res) {

    let getUser = await userController.FindUserById(req.userId);
    res.send(getUser);

});

router.post("/change-password", checkLogin, async function (req, res) {

    const user = await User.findById(req.userId);

    const valid = await bcrypt.compare(req.body.oldPassword, user.password);

    if (!valid) {
        return res.status(400).send({
            message: "Old password incorrect"
        });
    }

    const hash = await bcrypt.hash(req.body.newPassword, 10);

    user.password = hash;

    await user.save();

    res.send({
        message: "Password changed successfully"
    });

});

module.exports = router;