const jwt = require('jsonwebtoken');

const signJwt = (user) => {
    return jwt.sign({
        id: user.id,
        name: user.name,
        email: user.email,
    }, 'secret', { expiresIn: '30d' })
}

module.exports = {
    signJwt: signJwt
}