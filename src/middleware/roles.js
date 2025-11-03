function ensureRole(roles) {
	return (req, res, next) => {
		if (!req.isAuthenticated || !req.isAuthenticated()) return res.redirect('/login');
		if (!roles.includes(req.user.role)) return res.status(403).send('Forbidden');
		next();
	};
}

module.exports = { ensureRole };


