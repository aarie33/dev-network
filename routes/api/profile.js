const express = require('express');
const request = require('request');
const config = require('config');
const router = express.Router();
const Profile = require('../../models/Profile');
const User = require('../../models/User');
const Post = require('../../models/Post');
const auth = require('../../middleware/auth');
const { check, validationResult } = require('express-validator');

// @route   GET api/profile
// @desc    Test current users profile
// @access  Private
router.get('/me', auth, async (req, res) => {
	try {
		const profile = await Profile.findOne({
			user: req.user.id,
		}).populate('user', ['name', 'avatar']);

		if (!profile) {
			return res.status(400).json({ msg: 'No profile found' });
		}

		return res.json(profile);
	} catch (error) {
		res.status(500).json({ msg: 'Server error' });
	}
});

// @route   POST api/profile
// @desc    Create or update user profile
// @access  Private
router.post(
	'/',
	auth,
	[
		check('status', 'Status is required').not().isEmpty(),
		check('skills', 'Skills is required').not().isEmpty(),
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}
		const {
			company,
			website,
			location,
			bio,
			status,
			githubusername,
			skills,
			youtube,
			facebook,
			twitter,
			instagram,
			linkedin,
		} = req.body;

		// build profile object
		const profileFields = {};
		profileFields.user = req.user.id;
		if (company) profileFields.company = company;
		if (website) profileFields.website = website;
		if (location) profileFields.location = location;
		if (bio) profileFields.bio = bio;
		if (status) profileFields.status = status;
		if (githubusername) profileFields.githubusername = githubusername;
		if (skills) {
			profileFields.skills = skills
				.split(',')
				.map((skill) => skill.trim());
		}

		// build social object
		const socialfields = {
			youtube,
			twitter,
			instagram,
			linkedin,
			facebook,
		};
		if (youtube) socialfields.youtube = youtube;
		if (twitter) socialfields.twitter = twitter;
		if (facebook) socialfields.facebook = facebook;
		if (linkedin) socialfields.linkedin = linkedin;
		if (instagram) socialfields.instagram = instagram;
		profileFields.social = socialfields;

		try {
			let profile = await Profile.findOne({ user: req.user.id });

			if (profile) {
				// udpate
				profile = await Profile.findOneAndUpdate(
					{ user: req.user.id },
					{ $set: profileFields },
					{ new: true }
				);

				return res.json(profile);
			}

			// create
			profile = new Profile(profileFields);
			await profile.save();

			return res.json(profile);
		} catch (error) {
			res.status(500).json({ msg: 'Server error' });
		}
	}
);

// @route   GET api/profile
// @desc    Get all profiles
// @access  Public
router.get('/', async (req, res) => {
	try {
		const profiles = await Profile.find().populate('user', [
			'name',
			'avatar',
		]);
		res.json(profiles);
	} catch (error) {
		res.status(500).json({ msg: 'Server error' });
	}
});

// @route   GET api/profile/user/:user_id
// @desc    Get profile by user ID
// @access  Public
router.get('/user/:user_id', async (req, res) => {
	try {
		const profile = await Profile.findOne({
			user: req.params.user_id,
		}).populate('user', ['name', 'avatar']);

		if (!profile)
			return res.status(400).json({ msg: 'User profile not found' });
		res.json(profile);
	} catch (error) {
		if (error.kind === 'ObjectId') {
			return res.status(400).json({ msg: 'User profile not found' });
		}
		res.status(500).json({ msg: `Server error` });
	}
});

// @route   DELETE api/profile
// @desc    Delete profile, user & posts
// @access  Private
router.delete('/', auth, async (req, res) => {
	try {
		// remove user post
		await Post.deleteMany({ user: req.user.id });

		// remove profile
		await Profile.findOneAndRemove({ user: req.user.id });
		// remove user
		await User.findOneAndRemove({ _id: req.user.id });

		res.json({ msg: 'User deleted' });
	} catch (error) {
		res.status(500).json({ msg: `Server error` });
	}
});

// @route   PUT api/profile/experience
// @desc    Add profile experience
// @access  Private
router.put(
	'/experience',
	[
		auth,
		[
			check('title', 'Title is required').not().isEmpty(),
			check('company', 'Company is required').not().isEmpty(),
			check('from', 'From date is required').not().isEmpty(),
		],
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}

		const {
			title,
			company,
			location,
			from,
			to,
			current,
			description,
		} = req.body;

		const newExp = {
			title,
			company,
			location,
			from,
			to,
			current,
			description,
		};

		try {
			const profile = await Profile.findOne({ user: req.user.id });

			profile.experience.unshift(newExp);

			await profile.save();

			res.json(profile);
		} catch (error) {
			res.status(500).json({ msg: `Server error` });
		}
	}
);

// @route   DELETE api/profile/experience/:exp_id
// @desc    Delete experience from profile
// @access  Private
router.delete('/experience/:exp_id', auth, async (req, res) => {
	try {
		const profile = await Profile.findOne({ user: req.user.id });

		// get remove index
		const removeIndex = profile.experience
			.map((item) => item.id)
			.indexOf(req.params.exp_id);

		if (removeIndex >= 0) {
			profile.experience.splice(removeIndex, 1);

			await profile.save();

			res.json(profile);
		} else {
			res.status(400).json({ msg: `Experience ID not found` });
		}
	} catch (error) {
		res.status(500).json({ msg: `Server error` });
	}
});

// @route   PUT api/profile/education
// @desc    Add profile education
// @access  Private
router.put(
	'/education',
	[
		auth,
		[
			check('school', 'School is required').not().isEmpty(),
			check('degree', 'Degree is required').not().isEmpty(),
			check('fieldofstudy', 'Field of Study date is required')
				.not()
				.isEmpty(),
			check('from', 'From is required').not().isEmpty(),
		],
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}

		const {
			school,
			degree,
			fieldofstudy,
			from,
			to,
			current,
			description,
		} = req.body;

		const newEdu = {
			school,
			degree,
			fieldofstudy,
			from,
			to,
			current,
			description,
		};

		try {
			const profile = await Profile.findOne({ user: req.user.id });

			profile.education.unshift(newEdu);

			await profile.save();

			res.json(profile);
		} catch (error) {
			res.status(500).json({ msg: `Server error` });
		}
	}
);

// @route   DELETE api/profile/education/:edu_id
// @desc    Delete education from profile
// @access  Private
router.delete('/education/:edu_id', auth, async (req, res) => {
	try {
		const profile = await Profile.findOne({ user: req.user.id });

		// get remove index
		const removeIndex = profile.education
			.map((item) => item.id)
			.indexOf(req.params.edu_id);

		if (removeIndex >= 0) {
			profile.education.splice(removeIndex, 1);

			await profile.save();

			res.json(profile);
		} else {
			res.status(400).json({ msg: `Education ID not found` });
		}
	} catch (error) {
		res.status(500).json({ msg: `Server error` });
	}
});

// @route   GET api/profile/github/:username
// @desc    Get user repos from github
// @access  Public
router.get('/github/:username', (req, res) => {
	try {
		const options = {
			uri: `https://api.github.com/users/${
				req.params.username
			}/repos?per_page=5&sort=created:asc&client_id=${config.get(
				'githubClientId'
			)}&client_secret=${config.get('githubSecret')}`,
			method: 'get',
			headers: { 'user-agent': 'node.js' },
		};

		request(options, (error, response, body) => {
			if (error) console.error(error);

			if (response.statusCode !== 200) {
				return res.status(404).json({ msg: 'No Github profile found' });
			}

			return res.json(JSON.parse(body));
		});
	} catch (err) {
		res.status(500).json({ msg: `Server error` });
	}
});

module.exports = router;
