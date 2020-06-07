const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');
const auth = require('../../middleware/auth');
const User = require('../../models/User');

// @route   GET api/auth
// @desc    Test route
// @access  Protected
router.get('/', auth, async(req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).send('Server error');
    }
});

// @route   POST api/auth
// @desc    Authenticate user
// @access  Public
router.post(
    '/', [
        check('email', 'Email is required').isEmail(),
        check('password', 'Password is required').exists(),
    ],
    async(req, res) => {
        const error = validationResult(req);
        if (!error.isEmpty()) {
            return res.status(400).json({ errors: error.array() });
        }

        const { email, password } = req.body;

        try {
            let user = await User.findOne({ email });
            if (!user) {
                return res
                    .status(400)
                    .json({ errors: [{ msg: 'Invalid credential' }] });
            }

            const isMatch = await bcrypt.compare(password, user.password);

            if (!isMatch) {
                return res
                    .status(400)
                    .json({ errors: [{ msg: 'Invalid credential' }] });
            }

            const payload = {
                user: {
                    id: user.id,
                },
            };

            jwt.sign(
                payload,
                config.get('jwtSecret'), { expiresIn: 36000 },
                (err, token) => {
                    if (err) throw err;
                    return res.status(200).json({
                        user,
                        token,
                    });
                }
            );
        } catch (error) {
            return res.status(500).json({ msg: 'Server error' });
        }
    }
);
module.exports = router;