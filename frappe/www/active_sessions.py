import frappe

no_cache = 1

def get_context(context):
	frappe.only_for("System Manager")

	sessions = frappe.db.sql("""
		SELECT user, lastupdate
		FROM tabSessions
		WHERE user != 'Guest'
		ORDER BY lastupdate DESC
	""", as_dict=True)

	# Deduplicate: keep latest session per user
	seen = {}
	for s in sessions:
		if s.user not in seen:
			seen[s.user] = s

	context.sessions = list(seen.values())
	context.total = len(context.sessions)
