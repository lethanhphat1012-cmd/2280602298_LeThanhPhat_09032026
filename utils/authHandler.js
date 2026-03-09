let jwt = require('jsonwebtoken')
module.exports = {
    checkLogin: async function (req, res, next) {
        let token = req.headers.authorization;
        if (!token || !token.startsWith("Bearer")) {
            res.status(403).send("ban chua dang nhap")
            return;
        }
        token = token.split(' ')[1];
        let result = jwt.verify(token, 'secret');
        if (result && result.exp * 1000 > Date.now()) {
            req.userId = result.id;
            next();
        } else {
            res.status(403).send("ban chua dang nhap")
        }
    }
}


let userModel = require("../schemas/users");

async function checkLogin(req, res, next) {
    let token = req.headers.authorization;

    if (!token) {
        return res.status(401).send({ message: "Chua dang nhap" });
    }

    token = token.replace("Bearer ", "");

    try {
        let decoded = jwt.verify(token, "secret");
        req.userId = decoded.id;
        next();
    } catch (error) {
        return res.status(401).send({ message: "Token khong hop le" });
    }
}

// kiểm tra role
function checkRole(roles) {

    return async function (req, res, next) {

        let user = await userModel.findById(req.userId).populate("role");

        if (!user || !user.role) {
            return res.status(403).send({
                message: "User khong co role"
            });
        }

        if (!roles.includes(user.role.name)) {

            return res.status(403).send({
                message: "Khong co quyen"
            });

        }

        next();

    }

}

module.exports = {
    checkLogin,
    checkRole
};