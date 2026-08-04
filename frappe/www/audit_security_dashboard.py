import hmac
import json
import re
from datetime import timedelta

import frappe
from frappe.utils import add_days, cint, get_datetime, nowdate

no_cache = 1

_ALLOWED_ROLES = ["System Manager", "Auditor"]

# Extra gate on top of the role check: even a System Manager/Auditor must
# enter this password once per session before the page or any of its API
# endpoints will return data. Verified server-side (unlock_dashboard) and
# enforced in _ensure_access() for every whitelisted call below — not just
# the initial page load — so calling the API directly can't bypass it.
_DASHBOARD_PASSWORD = "mythos@123"
_DASHBOARD_UNLOCK_CACHE_PREFIX = "audit_dashboard_unlocked:"
_DASHBOARD_UNLOCK_TTL_SECONDS = 8 * 60 * 60

_MODULE_OPTIONS = ["Purchase", "Financial", "Project", "HR / Staff", "Deposits", "Travel", "IPR", "Other"]

_ACTIVITY_TYPES = ["Login", "Logout", "Impersonate", "Document Action", "Workflow Action"]

_DEFAULT_RANGE_DAYS = 30
_MAX_PAGE_LENGTH = 100
_DEFAULT_PAGE_LENGTH = 25

_SYSTEM_USERS = {"", "Guest"}

# 127.0.0.1 shows up whenever the request IP couldn't be resolved to a real
# client (server-side/internal calls) — it dominates the raw counts (hundreds
# of "users") without meaning anything as a shared IP, so it's excluded from
# IP-based analysis rather than flagged as suspicious.
_LOOPBACK_IPS = ("127.0.0.1", "::1", "localhost")
_LOOPBACK_IPS_SQL = "('" + "', '".join(_LOOPBACK_IPS) + "')"

_SHARED_IP_USER_THRESHOLD = 3
_MULTI_IP_USER_THRESHOLD = 3
_BUSINESS_HOUR_START = 8
_BUSINESS_HOUR_END = 20

# ── Risk scoring weights ───────────────────────────────────────────────
# Each factor contributes 0..its weight to a 0-100 score. Weights are additive
# and deliberately simple (no ML) so the score stays explainable to an auditor.
_RISK_WEIGHTS = {
	"failed_login_ratio": 30,   # share of login attempts that failed
	"multi_ip": 20,             # distinct IPs used, scaled against the threshold
	"off_hours_ratio": 20,      # share of logins outside business hours
	"impersonated": 15,         # was the target of an impersonation session
	"failed_admin_ratio": 15,   # share of admin-log events against them that failed
}
_RISK_BANDS = [(75, "Critical"), (50, "High"), (25, "Medium"), (0, "Low")]

_ANOMALY_OFF_HOURS_THRESHOLD = 3   # off-hours logins in range to flag a user
_ANOMALY_FAILED_BURST_THRESHOLD = 3  # failed logins in range to flag a user/IP

_DEVICE_UA_PATTERNS = [
	("Firefox", "browser", r"Firefox/"),
	("Edge", "browser", r"Edg/"),
	("Chrome", "browser", r"Chrome/"),
	("Safari", "browser", r"Safari/"),
	("curl", "script", r"^curl/"),
	("Python", "script", r"python-requests|Python-urllib"),
	("Postman", "script", r"PostmanRuntime"),
]
_DEVICE_OS_PATTERNS = [
	("Windows", r"Windows NT"),
	("macOS", r"Macintosh|Mac OS X"),
	("Android", r"Android"),
	("iOS", r"iPhone|iPad"),
	("Linux", r"Linux"),
]


def get_context(context):
	frappe.only_for(_ALLOWED_ROLES)
	context.module_options = _MODULE_OPTIONS
	context.activity_types = _ACTIVITY_TYPES
	context.dashboard_unlocked = _is_dashboard_unlocked()


def _is_dashboard_unlocked():
	if not frappe.session.sid:
		return False
	return bool(frappe.cache.get_value(_DASHBOARD_UNLOCK_CACHE_PREFIX + frappe.session.sid))


def _ensure_access():
	roles = frappe.get_roles()
	if not any(r in roles for r in _ALLOWED_ROLES):
		frappe.throw(frappe._("Not permitted to view audit data"), frappe.PermissionError)
	if not _is_dashboard_unlocked():
		frappe.throw(frappe._("Dashboard locked — enter the access password"), frappe.PermissionError)


@frappe.whitelist()
def unlock_dashboard(password):
	"""Verify the extra dashboard password and mark this session unlocked for
	_DASHBOARD_UNLOCK_TTL_SECONDS. Requires the role check to pass first —
	this is an additional gate, not a replacement for it."""
	roles = frappe.get_roles()
	if not any(r in roles for r in _ALLOWED_ROLES):
		frappe.throw(frappe._("Not permitted to view audit data"), frappe.PermissionError)
	if not hmac.compare_digest(str(password or ""), _DASHBOARD_PASSWORD):
		frappe.throw(frappe._("Incorrect password"), frappe.AuthenticationError)
	frappe.cache.set_value(
		_DASHBOARD_UNLOCK_CACHE_PREFIX + frappe.session.sid, "1", expires_in_sec=_DASHBOARD_UNLOCK_TTL_SECONDS
	)
	return {"unlocked": True}


def _date_bounds(date_from=None, date_to=None):
	"""Resolve a validated (from, to) datetime-string range, defaulting to the
	last _DEFAULT_RANGE_DAYS days. Bounding every query to a range keeps scans
	cheap as these log tables grow."""
	to_date = get_datetime(date_to).date() if date_to else get_datetime(nowdate()).date()
	if date_from:
		from_date = get_datetime(date_from).date()
	else:
		from_date = get_datetime(add_days(str(to_date), -_DEFAULT_RANGE_DAYS)).date()
	if from_date > to_date:
		from_date, to_date = to_date, from_date
	return f"{from_date} 00:00:00", f"{to_date} 23:59:59"


def _pagination(start, page_length):
	start = max(cint(start), 0)
	page_length = cint(page_length) or _DEFAULT_PAGE_LENGTH
	page_length = min(max(page_length, 1), _MAX_PAGE_LENGTH)
	return start, page_length


def _like(value):
	return f"%{value}%"


# ── Filter options ──────────────────────────────────────────────────────

@frappe.whitelist()
def get_filter_options():
	_ensure_access()

	users = set()
	for row in frappe.db.sql(
		"SELECT DISTINCT user FROM `tabActivity Log` WHERE user IS NOT NULL AND user != '' LIMIT 500",
		as_dict=True,
	):
		users.add(row.user)
	for row in frappe.db.sql(
		"SELECT DISTINCT user FROM `tabStaff Activity Log` WHERE user IS NOT NULL AND user != '' LIMIT 500",
		as_dict=True,
	):
		users.add(row.user)
	for row in frappe.db.sql(
		"SELECT DISTINCT user FROM `tabProRnd Admin Access Log` WHERE user IS NOT NULL AND user != '' LIMIT 500",
		as_dict=True,
	):
		users.add(row.user)
	users -= _SYSTEM_USERS

	full_names = {}
	if users:
		for row in frappe.db.get_all(
			"User", filters={"name": ["in", list(users)]}, fields=["name", "full_name"]
		):
			full_names[row.name] = row.full_name

	user_list = sorted(
		({"user": u, "full_name": full_names.get(u) or u} for u in users),
		key=lambda r: (r["full_name"] or "").lower(),
	)

	ips = set()
	for row in frappe.db.sql(
		"SELECT DISTINCT ip_address FROM `tabActivity Log` WHERE ip_address IS NOT NULL AND ip_address != '' LIMIT 500",
		as_dict=True,
	):
		ips.add(row.ip_address)
	for row in frappe.db.sql(
		"SELECT DISTINCT ip_address FROM `tabProRnd Admin Access Log` WHERE ip_address IS NOT NULL AND ip_address != '' LIMIT 500",
		as_dict=True,
	):
		ips.add(row.ip_address)
	ip_list = sorted(ips)

	return {
		"users": user_list,
		"ips": ip_list,
		"modules": _MODULE_OPTIONS,
		"activity_types": _ACTIVITY_TYPES,
	}


# ── KPIs ─────────────────────────────────────────────────────────────────

@frappe.whitelist()
def get_kpis(date_from=None, date_to=None, user=None, module=None, ip=None):
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)

	al_cond, al_params = "communication_date BETWEEN %s AND %s", [date_from, date_to]
	if user:
		al_cond += " AND user = %s"
		al_params.append(user)
	if ip:
		al_cond += " AND ip_address = %s"
		al_params.append(ip)

	login_rows = frappe.db.sql(
		f"""
		SELECT status, COUNT(*) AS cnt
		FROM `tabActivity Log`
		WHERE operation = 'Login' AND {al_cond}
		GROUP BY status
		""",
		al_params,
		as_dict=True,
	)
	successful_logins = sum(r.cnt for r in login_rows if r.status == "Success")
	failed_logins = sum(r.cnt for r in login_rows if r.status == "Failed")

	total_activity_log = frappe.db.sql(
		f"SELECT COUNT(*) AS cnt FROM `tabActivity Log` WHERE {al_cond}", al_params
	)[0][0]

	unique_users = frappe.db.sql(
		f"""
		SELECT COUNT(DISTINCT user) AS cnt FROM `tabActivity Log`
		WHERE {al_cond} AND user NOT IN ('', 'Guest')
		""",
		al_params,
	)[0][0]

	# Staff Activity Log carries no IP — it can't be attributed to an address,
	# so an IP filter excludes it entirely rather than showing an unfiltered total.
	workflow_actions = 0
	if not ip:
		sal_cond, sal_params = "timestamp BETWEEN %s AND %s", [date_from, date_to]
		if user:
			sal_cond += " AND user = %s"
			sal_params.append(user)
		if module:
			sal_cond += " AND form_category = %s"
			sal_params.append(module)

		workflow_actions = frappe.db.sql(
			f"SELECT COUNT(*) AS cnt FROM `tabStaff Activity Log` WHERE {sal_cond}", sal_params
		)[0][0]

	pal_cond, pal_params = "timestamp BETWEEN %s AND %s", [date_from, date_to]
	if user:
		pal_cond += " AND user = %s"
		pal_params.append(user)
	if ip:
		pal_cond += " AND ip_address = %s"
		pal_params.append(ip)

	admin_rows = frappe.db.sql(
		f"""
		SELECT event_type, status, COUNT(*) AS cnt
		FROM `tabProRnd Admin Access Log`
		WHERE {pal_cond}
		GROUP BY event_type, status
		""",
		pal_params,
		as_dict=True,
	)
	admin_actions = sum(r.cnt for r in admin_rows)
	impersonation_sessions = sum(r.cnt for r in admin_rows if r.event_type == "Impersonate")
	failed_admin_events = sum(r.cnt for r in admin_rows if r.status == "Failed")

	total_events = cint(total_activity_log) + cint(workflow_actions) + cint(admin_actions)
	failed_activities = cint(failed_logins) + cint(failed_admin_events)

	# Suspicious signal: IPs with repeated failed logins in range.
	suspicious_ips = frappe.db.sql(
		"""
		SELECT ip_address, COUNT(*) AS cnt
		FROM `tabActivity Log`
		WHERE operation = 'Login' AND status = 'Failed'
		  AND communication_date BETWEEN %s AND %s
		  AND ip_address IS NOT NULL AND ip_address != ''
		GROUP BY ip_address
		HAVING cnt >= 3
		""",
		[date_from, date_to],
	)

	distinct_ips = frappe.db.sql(
		f"""
		SELECT COUNT(DISTINCT ip_address) FROM `tabActivity Log`
		WHERE {al_cond} AND ip_address IS NOT NULL AND ip_address != '' AND ip_address NOT IN {_LOOPBACK_IPS_SQL}
		""",
		al_params,
	)[0][0]

	# Off-hours heuristic: successful logins outside the 08:00-20:00 business window.
	off_hours_logins = frappe.db.sql(
		f"""
		SELECT COUNT(*) FROM `tabActivity Log`
		WHERE operation = 'Login' AND status = 'Success' AND {al_cond}
		  AND (HOUR(communication_date) < 8 OR HOUR(communication_date) >= 20)
		""",
		al_params,
	)[0][0]

	return {
		"date_from": date_from,
		"date_to": date_to,
		"total_events": total_events,
		"successful_logins": cint(successful_logins),
		"failed_logins": cint(failed_logins),
		"unique_active_users": cint(unique_users),
		"admin_actions": cint(admin_actions),
		"impersonation_sessions": cint(impersonation_sessions),
		"workflow_actions": cint(workflow_actions),
		"failed_activities": failed_activities,
		"distinct_ip_count": cint(distinct_ips),
		"off_hours_logins": cint(off_hours_logins),
		"suspicious_ip_count": len(suspicious_ips),
	}


# ── Activity trend (for charting) ───────────────────────────────────────

@frappe.whitelist()
def get_activity_trend(date_from=None, date_to=None, user=None, module=None, ip=None):
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)

	al_cond, al_params = "communication_date BETWEEN %s AND %s", [date_from, date_to]
	if user:
		al_cond += " AND user = %s"
		al_params.append(user)
	if ip:
		al_cond += " AND ip_address = %s"
		al_params.append(ip)

	login_daily = frappe.db.sql(
		f"""
		SELECT DATE(communication_date) AS day, status, COUNT(*) AS cnt
		FROM `tabActivity Log`
		WHERE operation = 'Login' AND {al_cond}
		GROUP BY DATE(communication_date), status
		""",
		al_params,
		as_dict=True,
	)

	# Staff Activity Log has no IP column — excluded outright under an IP filter.
	workflow_daily = []
	if not ip:
		sal_cond, sal_params = "timestamp BETWEEN %s AND %s", [date_from, date_to]
		if user:
			sal_cond += " AND user = %s"
			sal_params.append(user)
		if module:
			sal_cond += " AND form_category = %s"
			sal_params.append(module)

		workflow_daily = frappe.db.sql(
			f"""
			SELECT DATE(timestamp) AS day, COUNT(*) AS cnt
			FROM `tabStaff Activity Log`
			WHERE {sal_cond}
			GROUP BY DATE(timestamp)
			""",
			sal_params,
			as_dict=True,
		)

	pal_cond, pal_params = "timestamp BETWEEN %s AND %s", [date_from, date_to]
	if user:
		pal_cond += " AND user = %s"
		pal_params.append(user)
	if ip:
		pal_cond += " AND ip_address = %s"
		pal_params.append(ip)

	admin_daily = frappe.db.sql(
		f"""
		SELECT DATE(timestamp) AS day, COUNT(*) AS cnt
		FROM `tabProRnd Admin Access Log`
		WHERE {pal_cond}
		GROUP BY DATE(timestamp)
		""",
		pal_params,
		as_dict=True,
	)

	days = {}
	start_date = get_datetime(date_from).date()
	end_date = get_datetime(date_to).date()
	d = start_date
	while d <= end_date:
		days[str(d)] = {
			"date": str(d),
			"logins_success": 0,
			"logins_failed": 0,
			"workflow_actions": 0,
			"admin_actions": 0,
		}
		d = get_datetime(add_days(str(d), 1)).date()

	for r in login_daily:
		day = str(r.day)
		if day not in days:
			continue
		if r.status == "Success":
			days[day]["logins_success"] += r.cnt
		elif r.status == "Failed":
			days[day]["logins_failed"] += r.cnt

	for r in workflow_daily:
		day = str(r.day)
		if day in days:
			days[day]["workflow_actions"] += r.cnt

	for r in admin_daily:
		day = str(r.day)
		if day in days:
			days[day]["admin_actions"] += r.cnt

	return sorted(days.values(), key=lambda r: r["date"])


# ── Peak access times ───────────────────────────────────────────────────

@frappe.whitelist()
def get_peak_access_times(date_from=None, date_to=None, user=None, ip=None):
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)

	cond, params = "operation = 'Login' AND communication_date BETWEEN %s AND %s", [date_from, date_to]
	if user:
		cond += " AND user = %s"
		params.append(user)
	if ip:
		cond += " AND ip_address = %s"
		params.append(ip)

	hour_rows = frappe.db.sql(
		f"""
		SELECT HOUR(communication_date) AS hr, COUNT(*) AS cnt
		FROM `tabActivity Log`
		WHERE {cond}
		GROUP BY HOUR(communication_date)
		""",
		params,
		as_dict=True,
	)
	weekday_rows = frappe.db.sql(
		f"""
		SELECT DAYOFWEEK(communication_date) AS wd, COUNT(*) AS cnt
		FROM `tabActivity Log`
		WHERE {cond}
		GROUP BY DAYOFWEEK(communication_date)
		""",
		params,
		as_dict=True,
	)

	by_hour = [0] * 24
	for r in hour_rows:
		if r.hr is not None:
			by_hour[cint(r.hr)] = r.cnt

	# DAYOFWEEK: 1=Sunday..7=Saturday -> remap to Mon..Sun for a natural week view.
	weekday_labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
	by_weekday = [0] * 7
	for r in weekday_rows:
		if r.wd is not None:
			idx = (cint(r.wd) + 5) % 7
			by_weekday[idx] = r.cnt

	peak_hour = max(range(24), key=lambda i: by_hour[i]) if any(by_hour) else None

	return {
		"by_hour": by_hour,
		"by_weekday": by_weekday,
		"weekday_labels": weekday_labels,
		"peak_hour": peak_hour,
	}


# ── Login / access history ──────────────────────────────────────────────

@frappe.whitelist()
def get_login_history(date_from=None, date_to=None, user=None, status=None, event_type=None, ip=None, start=0, page_length=25):
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)
	start, page_length = _pagination(start, page_length)

	if event_type in ("Login", "Logout"):
		cond = "operation = %s AND communication_date BETWEEN %s AND %s"
		params = [event_type, date_from, date_to]
	else:
		cond = "operation IN ('Login', 'Logout') AND communication_date BETWEEN %s AND %s"
		params = [date_from, date_to]
	if user:
		cond += " AND user = %s"
		params.append(user)
	if status:
		cond += " AND status = %s"
		params.append(status)
	if ip:
		cond += " AND ip_address = %s"
		params.append(ip)

	total = frappe.db.sql(f"SELECT COUNT(*) FROM `tabActivity Log` WHERE {cond}", params)[0][0]

	rows = frappe.db.sql(
		f"""
		SELECT name, user, full_name, operation, status, communication_date, ip_address
		FROM `tabActivity Log`
		WHERE {cond}
		ORDER BY communication_date DESC
		LIMIT %s OFFSET %s
		""",
		params + [page_length, start],
		as_dict=True,
	)

	return {"rows": rows, "total": cint(total), "start": start, "page_length": page_length}


# ── Failed / suspicious activities ──────────────────────────────────────

@frappe.whitelist()
def get_failed_activities(date_from=None, date_to=None, user=None, ip=None, start=0, page_length=25):
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)
	start, page_length = _pagination(start, page_length)

	al_cond = "status = 'Failed' AND communication_date BETWEEN %s AND %s"
	al_params = [date_from, date_to]
	if user:
		al_cond += " AND user = %s"
		al_params.append(user)
	if ip:
		al_cond += " AND ip_address = %s"
		al_params.append(ip)

	al_rows = frappe.db.sql(
		f"""
		SELECT user, operation, communication_date AS timestamp, ip_address, subject
		FROM `tabActivity Log`
		WHERE {al_cond}
		ORDER BY communication_date DESC
		LIMIT 500
		""",
		al_params,
		as_dict=True,
	)

	pal_cond = "status = 'Failed' AND timestamp BETWEEN %s AND %s"
	pal_params = [date_from, date_to]
	if user:
		pal_cond += " AND user = %s"
		pal_params.append(user)
	if ip:
		pal_cond += " AND ip_address = %s"
		pal_params.append(ip)

	pal_rows = frappe.db.sql(
		f"""
		SELECT user, event_type, timestamp, ip_address, details
		FROM `tabProRnd Admin Access Log`
		WHERE {pal_cond}
		ORDER BY timestamp DESC
		LIMIT 500
		""",
		pal_params,
		as_dict=True,
	)

	merged = []
	for r in al_rows:
		merged.append({
			"source": "Activity Log",
			"user": r.user,
			"event": r.operation or "Login",
			"timestamp": str(r.timestamp),
			"ip_address": r.ip_address,
			"detail": r.subject,
		})
	for r in pal_rows:
		merged.append({
			"source": "Admin Access Log",
			"user": r.user,
			"event": r.event_type,
			"timestamp": str(r.timestamp),
			"ip_address": r.ip_address,
			"detail": r.details,
		})

	merged.sort(key=lambda r: r["timestamp"], reverse=True)
	total = len(merged)
	page = merged[start:start + page_length]

	# Flag IPs with repeated failures within the returned window as suspicious.
	ip_counts = {}
	for r in merged:
		if r["ip_address"]:
			ip_counts[r["ip_address"]] = ip_counts.get(r["ip_address"], 0) + 1
	for r in page:
		r["suspicious"] = bool(r["ip_address"]) and ip_counts.get(r["ip_address"], 0) >= 3

	return {"rows": page, "total": total, "start": start, "page_length": page_length}


# ── Admin actions ────────────────────────────────────────────────────────

@frappe.whitelist()
def get_admin_actions(date_from=None, date_to=None, user=None, event_type=None, status=None, ip=None, start=0, page_length=25):
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)
	start, page_length = _pagination(start, page_length)

	cond = "timestamp BETWEEN %s AND %s"
	params = [date_from, date_to]
	if user:
		cond += " AND user = %s"
		params.append(user)
	if event_type:
		cond += " AND event_type = %s"
		params.append(event_type)
	if status:
		cond += " AND status = %s"
		params.append(status)
	if ip:
		cond += " AND ip_address = %s"
		params.append(ip)

	total = frappe.db.sql(f"SELECT COUNT(*) FROM `tabProRnd Admin Access Log` WHERE {cond}", params)[0][0]

	rows = frappe.db.sql(
		f"""
		SELECT name, timestamp, user, event_type, target_user, status,
		       action_doctype, action_docname, action_type, ip_address, details
		FROM `tabProRnd Admin Access Log`
		WHERE {cond}
		ORDER BY timestamp DESC
		LIMIT %s OFFSET %s
		""",
		params + [page_length, start],
		as_dict=True,
	)

	return {"rows": rows, "total": cint(total), "start": start, "page_length": page_length}


# ── User-wise activity ───────────────────────────────────────────────────

@frappe.whitelist()
def get_user_activity(date_from=None, date_to=None, module=None, ip=None, start=0, page_length=25):
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)
	start, page_length = _pagination(start, page_length)

	al_cond = "communication_date BETWEEN %s AND %s AND user NOT IN ('', 'Guest')"
	al_params = [date_from, date_to]
	if ip:
		al_cond += " AND ip_address = %s"
		al_params.append(ip)

	login_rows = frappe.db.sql(
		f"""
		SELECT user,
		       SUM(CASE WHEN operation = 'Login' AND status = 'Success' THEN 1 ELSE 0 END) AS logins,
		       SUM(CASE WHEN operation = 'Login' AND status = 'Failed' THEN 1 ELSE 0 END) AS failed_logins,
		       MAX(communication_date) AS last_active
		FROM `tabActivity Log`
		WHERE {al_cond}
		GROUP BY user
		""",
		al_params,
		as_dict=True,
	)

	# Staff Activity Log has no IP column — excluded outright under an IP filter.
	workflow_rows = []
	if not ip:
		sal_cond = "timestamp BETWEEN %s AND %s"
		sal_params = [date_from, date_to]
		if module:
			sal_cond += " AND form_category = %s"
			sal_params.append(module)

		workflow_rows = frappe.db.sql(
			f"""
			SELECT user, COUNT(*) AS cnt, MAX(timestamp) AS last_active
			FROM `tabStaff Activity Log`
			WHERE {sal_cond}
			GROUP BY user
			""",
			sal_params,
			as_dict=True,
		)

	pal_cond = "timestamp BETWEEN %s AND %s"
	pal_params = [date_from, date_to]
	if ip:
		pal_cond += " AND ip_address = %s"
		pal_params.append(ip)

	admin_rows = frappe.db.sql(
		f"""
		SELECT user, COUNT(*) AS cnt, MAX(timestamp) AS last_active
		FROM `tabProRnd Admin Access Log`
		WHERE {pal_cond}
		GROUP BY user
		""",
		pal_params,
		as_dict=True,
	)

	stats = {}

	def bucket(user):
		return stats.setdefault(user, {
			"user": user, "logins": 0, "failed_logins": 0,
			"workflow_actions": 0, "admin_actions": 0, "last_active": None,
		})

	def bump_last_active(entry, ts):
		if ts and (not entry["last_active"] or str(ts) > str(entry["last_active"])):
			entry["last_active"] = ts

	for r in login_rows:
		e = bucket(r.user)
		e["logins"] = cint(r.logins)
		e["failed_logins"] = cint(r.failed_logins)
		bump_last_active(e, r.last_active)

	for r in workflow_rows:
		if not r.user:
			continue
		e = bucket(r.user)
		e["workflow_actions"] = cint(r.cnt)
		bump_last_active(e, r.last_active)

	for r in admin_rows:
		if not r.user:
			continue
		e = bucket(r.user)
		e["admin_actions"] = cint(r.cnt)
		bump_last_active(e, r.last_active)

	users = list(stats.keys())
	full_names = {}
	if users:
		for row in frappe.db.get_all("User", filters={"name": ["in", users]}, fields=["name", "full_name"]):
			full_names[row.name] = row.full_name

	result = []
	for u, e in stats.items():
		e["full_name"] = full_names.get(u) or u
		e["total"] = e["logins"] + e["failed_logins"] + e["workflow_actions"] + e["admin_actions"]
		e["last_active"] = str(e["last_active"]) if e["last_active"] else None
		result.append(e)

	result.sort(key=lambda r: r["total"], reverse=True)
	total = len(result)
	page = result[start:start + page_length]

	return {"rows": page, "total": total, "start": start, "page_length": page_length}


# ── Recent audit logs (merged feed) ─────────────────────────────────────

@frappe.whitelist()
def get_recent_audit_logs(date_from=None, date_to=None, user=None, activity_type=None, module=None, ip=None, start=0, page_length=25):
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)
	start, page_length = _pagination(start, page_length)

	# Merge-top-K: fetch at most (start + page_length) most-recent rows from
	# each source (each already indexed/ordered by its own timestamp column),
	# merge, sort, then slice — avoids a 3-way UNION table scan while staying
	# correct, since no source can contribute more rows than the final page needs.
	fetch_n = start + page_length

	merged = []

	if not activity_type or activity_type in ("Login", "Logout", "Impersonate"):
		al_cond = "communication_date BETWEEN %s AND %s"
		al_params = [date_from, date_to]
		if user:
			al_cond += " AND user = %s"
			al_params.append(user)
		if ip:
			al_cond += " AND ip_address = %s"
			al_params.append(ip)
		if activity_type:
			al_cond += " AND operation = %s"
			al_params.append(activity_type)
		else:
			al_cond += " AND operation IN ('Login', 'Logout', 'Impersonate')"

		# Activity Log logs 'Impersonate' under the TARGET user, not the actor
		# — ProRnd Admin Access Log (below) carries the same event correctly
		# attributed (actor, target, real IP) *when it has a match*, but that
		# doctype was only deployed 2026-07-28; everything before that has no
		# Admin Access Log counterpart at all and is the only record of those
		# impersonation sessions that exists. So: skip an Activity Log
		# 'Impersonate' row only when a matching Admin Access Log row is
		# actually found (same target, within a few seconds) — otherwise keep
		# it, just labelled so it doesn't read as the target impersonating
		# themselves.
		imp_map = _impersonation_timestamps(date_from, date_to) if (not activity_type or activity_type == "Impersonate") else {}

		for r in frappe.db.sql(
			f"""
			SELECT user, full_name, operation, status, communication_date AS ts, ip_address, subject
			FROM `tabActivity Log`
			WHERE {al_cond}
			ORDER BY communication_date DESC
			LIMIT {fetch_n}
			""",
			al_params,
			as_dict=True,
		):
			if r.operation == "Impersonate" and _is_impersonation_artifact(get_datetime(r.ts), imp_map.get(r.user)):
				continue
			merged.append({
				"source": "Activity Log",
				"timestamp": str(r.ts),
				"user": r.user,
				"full_name": r.full_name,
				"event": "Impersonated (target)" if r.operation == "Impersonate" else (r.operation or "Login"),
				"status": r.status,
				"detail": r.subject,
				"ip_address": r.ip_address,
			})

	# Staff Activity Log has no IP column — excluded outright under an IP filter.
	if not ip and (not activity_type or activity_type == "Workflow Action"):
		sal_cond = "timestamp BETWEEN %s AND %s"
		sal_params = [date_from, date_to]
		if user:
			sal_cond += " AND user = %s"
			sal_params.append(user)
		if module:
			sal_cond += " AND form_category = %s"
			sal_params.append(module)

		for r in frappe.db.sql(
			f"""
			SELECT user, timestamp AS ts, doctype_name, document_name, action, form_category
			FROM `tabStaff Activity Log`
			WHERE {sal_cond}
			ORDER BY timestamp DESC
			LIMIT {fetch_n}
			""",
			sal_params,
			as_dict=True,
		):
			merged.append({
				"source": "Staff Activity Log",
				"timestamp": str(r.ts),
				"user": r.user,
				"full_name": None,
				"event": r.action or "Workflow Action",
				"status": None,
				"detail": f"{r.doctype_name} {r.document_name} ({r.form_category or 'Other'})",
				"ip_address": None,
			})

	if not activity_type or activity_type in ("Login", "Logout", "Impersonate", "Document Action"):
		pal_cond = "timestamp BETWEEN %s AND %s"
		pal_params = [date_from, date_to]
		if user:
			# Match the filtered user as either actor or target — otherwise
			# filtering by an impersonated user's own login hides the very
			# impersonation event that explains their Activity Log entries.
			pal_cond += " AND (user = %s OR target_user = %s)"
			pal_params.append(user)
			pal_params.append(user)
		if ip:
			pal_cond += " AND ip_address = %s"
			pal_params.append(ip)
		if activity_type:
			pal_cond += " AND event_type = %s"
			pal_params.append(activity_type)

		for r in frappe.db.sql(
			f"""
			SELECT user, target_user, event_type, status, timestamp AS ts, ip_address, details
			FROM `tabProRnd Admin Access Log`
			WHERE {pal_cond}
			ORDER BY timestamp DESC
			LIMIT {fetch_n}
			""",
			pal_params,
			as_dict=True,
		):
			merged.append({
				"source": "Admin Access Log",
				"timestamp": str(r.ts),
				"user": r.user,
				"full_name": None,
				"event": r.event_type,
				"status": r.status,
				"detail": r.details or (f"target: {r.target_user}" if r.target_user else ""),
				"ip_address": r.ip_address,
			})

	merged.sort(key=lambda r: r["timestamp"], reverse=True)
	page = merged[start:start + page_length]

	return {"rows": page, "start": start, "page_length": page_length, "has_more": len(merged) > start + page_length}


# ── IP address analysis ──────────────────────────────────────────────────

@frappe.whitelist()
def get_ip_activity(date_from=None, date_to=None, user=None, ip=None, start=0, page_length=25):
	"""Group all logged access by IP address: volume, success/failure split,
	how many distinct users touched it, and the first/last time seen."""
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)
	start, page_length = _pagination(start, page_length)

	al_cond = "ip_address IS NOT NULL AND ip_address != '' AND communication_date BETWEEN %s AND %s"
	al_params = [date_from, date_to]
	if user:
		al_cond += " AND user = %s"
		al_params.append(user)
	if ip:
		al_cond += " AND ip_address = %s"
		al_params.append(ip)

	al_rows = frappe.db.sql(
		f"""
		SELECT ip_address,
		       COUNT(*) AS total,
		       SUM(CASE WHEN status = 'Success' THEN 1 ELSE 0 END) AS success,
		       SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed,
		       COUNT(DISTINCT user) AS distinct_users,
		       MIN(communication_date) AS first_seen,
		       MAX(communication_date) AS last_seen
		FROM `tabActivity Log`
		WHERE {al_cond}
		GROUP BY ip_address
		""",
		al_params,
		as_dict=True,
	)

	pal_cond = "ip_address IS NOT NULL AND ip_address != '' AND timestamp BETWEEN %s AND %s"
	pal_params = [date_from, date_to]
	if user:
		pal_cond += " AND user = %s"
		pal_params.append(user)
	if ip:
		pal_cond += " AND ip_address = %s"
		pal_params.append(ip)

	pal_rows = frappe.db.sql(
		f"""
		SELECT ip_address,
		       COUNT(*) AS total,
		       SUM(CASE WHEN status = 'Success' THEN 1 ELSE 0 END) AS success,
		       SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed,
		       COUNT(DISTINCT user) AS distinct_users,
		       MIN(timestamp) AS first_seen,
		       MAX(timestamp) AS last_seen
		FROM `tabProRnd Admin Access Log`
		WHERE {pal_cond}
		GROUP BY ip_address
		""",
		pal_params,
		as_dict=True,
	)

	stats = {}
	for r in al_rows + pal_rows:
		e = stats.setdefault(r.ip_address, {
			"ip_address": r.ip_address, "total": 0, "success": 0, "failed": 0,
			"distinct_users": 0, "first_seen": None, "last_seen": None,
		})
		e["total"] += cint(r.total)
		e["success"] += cint(r.success)
		e["failed"] += cint(r.failed)
		e["distinct_users"] = max(e["distinct_users"], cint(r.distinct_users))
		if r.first_seen and (not e["first_seen"] or str(r.first_seen) < str(e["first_seen"])):
			e["first_seen"] = r.first_seen
		if r.last_seen and (not e["last_seen"] or str(r.last_seen) > str(e["last_seen"])):
			e["last_seen"] = r.last_seen

	# Attach a small sample of users per IP for display, without a huge join.
	if stats:
		ips = list(stats.keys())
		user_rows = frappe.db.sql(
			f"""
			SELECT ip_address, user FROM `tabActivity Log`
			WHERE ip_address IN ({", ".join(["%s"] * len(ips))})
			  AND communication_date BETWEEN %s AND %s AND user NOT IN ('', 'Guest')
			GROUP BY ip_address, user
			""",
			ips + [date_from, date_to],
			as_dict=True,
		)
		samples = {}
		for r in user_rows:
			samples.setdefault(r.ip_address, [])
			if len(samples[r.ip_address]) < 4:
				samples[r.ip_address].append(r.user)
		for ip, e in stats.items():
			e["users_sample"] = samples.get(ip, [])
			e["is_internal"] = ip in _LOOPBACK_IPS
			e["first_seen"] = str(e["first_seen"]) if e["first_seen"] else None
			e["last_seen"] = str(e["last_seen"]) if e["last_seen"] else None

	result = list(stats.values())
	result.sort(key=lambda r: r["total"], reverse=True)
	total = len(result)
	page = result[start:start + page_length]

	return {"rows": page, "total": total, "start": start, "page_length": page_length}


@frappe.whitelist()
def get_ip_insights(date_from=None, date_to=None):
	"""Advanced IP-based security signals:
	- Shared IPs: one address used by unusually many distinct users (excludes
	  loopback, which is a proxy-resolution artifact, not a real shared IP).
	- Multi-IP users: one account logging in from unusually many addresses.
	- New IPs: addresses seen in this range that were never seen in the
	  equal-length window immediately before it — a first-seen/anomaly signal.
	"""
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)

	shared_ips = frappe.db.sql(
		f"""
		SELECT ip_address, COUNT(DISTINCT user) AS distinct_users, COUNT(*) AS total
		FROM `tabActivity Log`
		WHERE communication_date BETWEEN %s AND %s
		  AND ip_address IS NOT NULL AND ip_address != '' AND ip_address NOT IN {_LOOPBACK_IPS_SQL}
		  AND user NOT IN ('', 'Guest')
		GROUP BY ip_address
		HAVING distinct_users >= {_SHARED_IP_USER_THRESHOLD}
		ORDER BY distinct_users DESC
		LIMIT 15
		""",
		[date_from, date_to],
		as_dict=True,
	)

	multi_ip_users = frappe.db.sql(
		f"""
		SELECT user, COUNT(DISTINCT ip_address) AS distinct_ips, COUNT(*) AS total
		FROM `tabActivity Log`
		WHERE communication_date BETWEEN %s AND %s
		  AND ip_address IS NOT NULL AND ip_address != '' AND ip_address NOT IN {_LOOPBACK_IPS_SQL}
		  AND user NOT IN ('', 'Guest')
		GROUP BY user
		HAVING distinct_ips >= {_MULTI_IP_USER_THRESHOLD}
		ORDER BY distinct_ips DESC
		LIMIT 15
		""",
		[date_from, date_to],
		as_dict=True,
	)

	# Compare against the equal-length window immediately before date_from.
	range_days = max(1, (get_datetime(date_to).date() - get_datetime(date_from).date()).days)
	prev_to = get_datetime(date_from).date()
	prev_from = get_datetime(add_days(str(prev_to), -range_days)).date()

	current_ips = {
		r.ip_address for r in frappe.db.sql(
			f"""
			SELECT DISTINCT ip_address FROM `tabActivity Log`
			WHERE communication_date BETWEEN %s AND %s
			  AND ip_address IS NOT NULL AND ip_address != '' AND ip_address NOT IN {_LOOPBACK_IPS_SQL}
			""",
			[date_from, date_to],
			as_dict=True,
		)
	}
	prior_ips = {
		r.ip_address for r in frappe.db.sql(
			f"""
			SELECT DISTINCT ip_address FROM `tabActivity Log`
			WHERE communication_date BETWEEN %s AND %s
			  AND ip_address IS NOT NULL AND ip_address != '' AND ip_address NOT IN {_LOOPBACK_IPS_SQL}
			""",
			[f"{prev_from} 00:00:00", f"{prev_to} 23:59:59"],
			as_dict=True,
		)
	}
	new_ip_set = current_ips - prior_ips

	new_ips = []
	if new_ip_set:
		rows = frappe.db.sql(
			f"""
			SELECT ip_address, COUNT(DISTINCT user) AS distinct_users, COUNT(*) AS total, MIN(communication_date) AS first_seen
			FROM `tabActivity Log`
			WHERE communication_date BETWEEN %s AND %s
			  AND ip_address IN ({", ".join(["%s"] * len(new_ip_set))})
			GROUP BY ip_address
			ORDER BY first_seen DESC
			LIMIT 20
			""",
			[date_from, date_to] + list(new_ip_set),
			as_dict=True,
		)
		new_ips = [{
			"ip_address": r.ip_address,
			"distinct_users": cint(r.distinct_users),
			"total": cint(r.total),
			"first_seen": str(r.first_seen),
		} for r in rows]

	return {
		"shared_ips": shared_ips,
		"multi_ip_users": multi_ip_users,
		"new_ips": new_ips,
		"shared_ip_threshold": _SHARED_IP_USER_THRESHOLD,
		"multi_ip_threshold": _MULTI_IP_USER_THRESHOLD,
	}


@frappe.whitelist()
def get_ip_detail(ip_address, date_from=None, date_to=None):
	"""Drill-down for a single IP address: overall summary, a per-user
	breakdown of who used it, and its most recent events — shown when a user
	clicks an IP anywhere in the dashboard."""
	_ensure_access()
	if not ip_address:
		frappe.throw(frappe._("ip_address is required"))
	date_from, date_to = _date_bounds(date_from, date_to)

	al_summary = frappe.db.sql(
		"""
		SELECT COUNT(*) AS total,
		       SUM(CASE WHEN status = 'Success' THEN 1 ELSE 0 END) AS success,
		       SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed,
		       COUNT(DISTINCT user) AS distinct_users,
		       MIN(communication_date) AS first_seen,
		       MAX(communication_date) AS last_seen
		FROM `tabActivity Log`
		WHERE ip_address = %s AND communication_date BETWEEN %s AND %s
		""",
		[ip_address, date_from, date_to],
		as_dict=True,
	)[0]

	pal_summary = frappe.db.sql(
		"""
		SELECT COUNT(*) AS total,
		       SUM(CASE WHEN status = 'Success' THEN 1 ELSE 0 END) AS success,
		       SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed,
		       COUNT(DISTINCT user) AS distinct_users,
		       MIN(timestamp) AS first_seen,
		       MAX(timestamp) AS last_seen
		FROM `tabProRnd Admin Access Log`
		WHERE ip_address = %s AND timestamp BETWEEN %s AND %s
		""",
		[ip_address, date_from, date_to],
		as_dict=True,
	)[0]

	def _min(a, b):
		vals = [str(v) for v in (a, b) if v]
		return min(vals) if vals else None

	def _max(a, b):
		vals = [str(v) for v in (a, b) if v]
		return max(vals) if vals else None

	summary = {
		"ip_address": ip_address,
		"is_internal": ip_address in _LOOPBACK_IPS,
		"total": cint(al_summary.total) + cint(pal_summary.total),
		"success": cint(al_summary.success) + cint(pal_summary.success),
		"failed": cint(al_summary.failed) + cint(pal_summary.failed),
		"first_seen": _min(al_summary.first_seen, pal_summary.first_seen),
		"last_seen": _max(al_summary.last_seen, pal_summary.last_seen),
	}

	# Per-user breakdown: who used this IP, and how.
	user_rows = frappe.db.sql(
		"""
		SELECT user,
		       SUM(CASE WHEN status = 'Success' THEN 1 ELSE 0 END) AS success,
		       SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed,
		       COUNT(*) AS total,
		       MIN(communication_date) AS first_seen,
		       MAX(communication_date) AS last_seen
		FROM `tabActivity Log`
		WHERE ip_address = %s AND communication_date BETWEEN %s AND %s AND user NOT IN ('', 'Guest')
		GROUP BY user
		""",
		[ip_address, date_from, date_to],
		as_dict=True,
	)
	pal_user_rows = frappe.db.sql(
		"""
		SELECT user,
		       SUM(CASE WHEN status = 'Success' THEN 1 ELSE 0 END) AS success,
		       SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed,
		       COUNT(*) AS total,
		       MIN(timestamp) AS first_seen,
		       MAX(timestamp) AS last_seen
		FROM `tabProRnd Admin Access Log`
		WHERE ip_address = %s AND timestamp BETWEEN %s AND %s
		GROUP BY user
		""",
		[ip_address, date_from, date_to],
		as_dict=True,
	)

	users = {}
	for r in user_rows + pal_user_rows:
		if not r.user:
			continue
		e = users.setdefault(r.user, {"user": r.user, "total": 0, "success": 0, "failed": 0, "first_seen": None, "last_seen": None})
		e["total"] += cint(r.total)
		e["success"] += cint(r.success)
		e["failed"] += cint(r.failed)
		e["first_seen"] = _min(e["first_seen"], r.first_seen)
		e["last_seen"] = _max(e["last_seen"], r.last_seen)

	full_names = {}
	if users:
		for row in frappe.db.get_all("User", filters={"name": ["in", list(users.keys())]}, fields=["name", "full_name"]):
			full_names[row.name] = row.full_name
	for u, e in users.items():
		e["full_name"] = full_names.get(u) or u

	user_breakdown = sorted(users.values(), key=lambda r: r["total"], reverse=True)

	# Most recent events from this IP, merged across sources.
	events = []
	for r in frappe.db.sql(
		"""
		SELECT user, full_name, operation, status, communication_date AS ts, subject
		FROM `tabActivity Log`
		WHERE ip_address = %s AND communication_date BETWEEN %s AND %s
		ORDER BY communication_date DESC
		LIMIT 100
		""",
		[ip_address, date_from, date_to],
		as_dict=True,
	):
		events.append({
			"source": "Activity Log", "timestamp": str(r.ts), "user": r.user,
			"event": r.operation or "Login", "status": r.status, "detail": r.subject,
		})
	for r in frappe.db.sql(
		"""
		SELECT user, target_user, event_type, status, timestamp AS ts, details
		FROM `tabProRnd Admin Access Log`
		WHERE ip_address = %s AND timestamp BETWEEN %s AND %s
		ORDER BY timestamp DESC
		LIMIT 100
		""",
		[ip_address, date_from, date_to],
		as_dict=True,
	):
		events.append({
			"source": "Admin Access Log", "timestamp": str(r.ts), "user": r.user,
			"event": r.event_type, "status": r.status,
			"detail": r.details or (f"target: {r.target_user}" if r.target_user else ""),
		})

	events.sort(key=lambda r: r["timestamp"], reverse=True)

	return {
		"summary": summary,
		"user_breakdown": user_breakdown,
		"events": events[:100],
	}


# ── Access heatmap (weekday x hour) ──────────────────────────────────────

@frappe.whitelist()
def get_access_heatmap(date_from=None, date_to=None, user=None, ip=None):
	"""Login volume as a weekday x hour grid — the enterprise-dashboard
	heatmap view of get_peak_access_times' two flat breakdowns."""
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)

	cond, params = "operation = 'Login' AND communication_date BETWEEN %s AND %s", [date_from, date_to]
	if user:
		cond += " AND user = %s"
		params.append(user)
	if ip:
		cond += " AND ip_address = %s"
		params.append(ip)

	rows = frappe.db.sql(
		f"""
		SELECT DAYOFWEEK(communication_date) AS wd, HOUR(communication_date) AS hr, COUNT(*) AS cnt
		FROM `tabActivity Log`
		WHERE {cond}
		GROUP BY DAYOFWEEK(communication_date), HOUR(communication_date)
		""",
		params,
		as_dict=True,
	)

	weekday_labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
	grid = [[0] * 24 for _ in range(7)]
	peak = {"weekday": None, "hour": None, "count": 0}
	for r in rows:
		if r.wd is None or r.hr is None:
			continue
		wd_idx = (cint(r.wd) + 5) % 7
		grid[wd_idx][cint(r.hr)] = r.cnt
		if r.cnt > peak["count"]:
			peak = {"weekday": weekday_labels[wd_idx], "hour": cint(r.hr), "count": r.cnt}
	# ── Date-wise grid: one row per actual calendar date ──────────────
	date_rows = frappe.db.sql(
		f"""
		SELECT DATE(communication_date) AS dt, HOUR(communication_date) AS hr, COUNT(*) AS cnt
		FROM `tabActivity Log`
		WHERE {cond}
		GROUP BY DATE(communication_date), HOUR(communication_date)
		ORDER BY dt
		""",
		params,
		as_dict=True,
	)

	all_dates = sorted({str(r.dt) for r in date_rows if r.dt is not None})
	date_idx = {d: i for i, d in enumerate(all_dates)}
	date_grid = [[0] * 24 for _ in range(len(all_dates))]
	for r in date_rows:
		if r.dt is None or r.hr is None:
			continue
		di = date_idx.get(str(r.dt))
		if di is not None:
			date_grid[di][cint(r.hr)] = cint(r.cnt)

	# Shorten labels to MM-DD for the heatmap row labels; full ISO dates
	# are recoverable from the index position if needed.
	date_labels = [d[5:] for d in all_dates]  # "07-28", "07-29", …

	return {
		"grid": grid,
		"weekday_labels": weekday_labels,
		"peak": peak,
		"date_grid": date_grid,
		"date_labels": date_labels,
	}


# ── Module access analytics ──────────────────────────────────────────────

@frappe.whitelist()
def get_module_access(date_from=None, date_to=None, user=None):
	"""Workflow-action volume per module (form_category), with an
	approve/reject/forward breakdown so it doubles as a lightweight
	throughput/quality view per business area."""
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)

	cond = "timestamp BETWEEN %s AND %s"
	params = [date_from, date_to]
	if user:
		cond += " AND user = %s"
		params.append(user)

	rows = frappe.db.sql(
		f"""
		SELECT COALESCE(NULLIF(form_category, ''), 'Other') AS module, action, COUNT(*) AS cnt
		FROM `tabStaff Activity Log`
		WHERE {cond}
		GROUP BY module, action
		""",
		params,
		as_dict=True,
	)

	modules = {}
	for r in rows:
		m = modules.setdefault(r.module, {
			"module": r.module, "total": 0, "approved": 0, "rejected": 0, "submitted": 0, "forwarded": 0,
		})
		m["total"] += cint(r.cnt)
		if r.action == "Approve":
			m["approved"] += cint(r.cnt)
		elif r.action == "Reject":
			m["rejected"] += cint(r.cnt)
		elif r.action == "Submit":
			m["submitted"] += cint(r.cnt)
		elif r.action == "Forward":
			m["forwarded"] += cint(r.cnt)

	result = sorted(modules.values(), key=lambda r: r["total"], reverse=True)
	return {"modules": result}


# ── Device / client analysis ─────────────────────────────────────────────

def _classify_user_agent(ua):
	if not ua:
		return None, None
	client = "Other"
	kind = "browser"
	for name, k, pattern in _DEVICE_UA_PATTERNS:
		if re.search(pattern, ua):
			client, kind = name, k
			break
	os_name = "Other"
	for name, pattern in _DEVICE_OS_PATTERNS:
		if re.search(pattern, ua):
			os_name = name
			break
	return {"client": client, "kind": kind}, os_name


@frappe.whitelist()
def get_device_analysis(date_from=None, date_to=None):
	"""Browser/OS breakdown parsed from the one source that records a
	User-Agent (ProRnd Admin Access Log). Non-browser clients (curl, scripts,
	API tools) are called out separately since a scripted login against an
	admin-bypass account is itself a security-relevant signal."""
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)

	rows = frappe.db.sql(
		"""
		SELECT user, user_agent, COUNT(*) AS cnt, MAX(timestamp) AS last_seen
		FROM `tabProRnd Admin Access Log`
		WHERE timestamp BETWEEN %s AND %s AND user_agent IS NOT NULL AND user_agent != ''
		GROUP BY user, user_agent
		""",
		[date_from, date_to],
		as_dict=True,
	)

	browsers, os_counts, scripts = {}, {}, {}
	total = 0
	for r in rows:
		client, os_name = _classify_user_agent(r.user_agent)
		if not client:
			continue
		total += cint(r.cnt)
		os_counts[os_name] = os_counts.get(os_name, 0) + cint(r.cnt)
		if client["kind"] == "script":
			e = scripts.setdefault(client["client"], {"client": client["client"], "count": 0, "users": set(), "last_seen": None})
			e["count"] += cint(r.cnt)
			if r.user:
				e["users"].add(r.user)
			if not e["last_seen"] or str(r.last_seen) > str(e["last_seen"]):
				e["last_seen"] = r.last_seen
		else:
			browsers[client["client"]] = browsers.get(client["client"], 0) + cint(r.cnt)

	script_list = [{
		"client": e["client"], "count": e["count"], "users": sorted(e["users"]), "last_seen": str(e["last_seen"]),
	} for e in scripts.values()]
	script_list.sort(key=lambda r: r["count"], reverse=True)

	return {
		"total": total,
		"browsers": sorted(({"name": k, "count": v} for k, v in browsers.items()), key=lambda r: r["count"], reverse=True),
		"os": sorted(({"name": k, "count": v} for k, v in os_counts.items()), key=lambda r: r["count"], reverse=True),
		"scripts": script_list,
	}


# ── Risk scoring ──────────────────────────────────────────────────────────

def _risk_band(score):
	for threshold, label in _RISK_BANDS:
		if score >= threshold:
			return label
	return "Low"


def _compute_risk_scores(date_from, date_to, user_filter=None):
	"""Shared core for get_risk_scores and get_user_detail: builds a per-user
	risk profile from five explainable, additive factors (see _RISK_WEIGHTS)
	rather than an opaque ML score, so an auditor can see exactly why a user
	is flagged."""
	user_cond = ""
	user_params = []
	if user_filter:
		user_cond = " AND user = %s"
		user_params = [user_filter]

	login_rows = frappe.db.sql(
		f"""
		SELECT user,
		       SUM(CASE WHEN status = 'Success' THEN 1 ELSE 0 END) AS success,
		       SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed,
		       SUM(CASE WHEN status = 'Success' AND (HOUR(communication_date) < {_BUSINESS_HOUR_START} OR HOUR(communication_date) >= {_BUSINESS_HOUR_END}) THEN 1 ELSE 0 END) AS off_hours
		FROM `tabActivity Log`
		WHERE operation = 'Login' AND communication_date BETWEEN %s AND %s AND user NOT IN ('', 'Guest') {user_cond}
		GROUP BY user
		""",
		[date_from, date_to] + user_params,
		as_dict=True,
	)

	ip_rows = frappe.db.sql(
		f"""
		SELECT user, COUNT(DISTINCT ip_address) AS distinct_ips
		FROM `tabActivity Log`
		WHERE communication_date BETWEEN %s AND %s AND user NOT IN ('', 'Guest')
		  AND ip_address IS NOT NULL AND ip_address != '' AND ip_address NOT IN {_LOOPBACK_IPS_SQL} {user_cond}
		GROUP BY user
		""",
		[date_from, date_to] + user_params,
		as_dict=True,
	)

	target_cond = ""
	target_params = []
	if user_filter:
		target_cond = " AND target_user = %s"
		target_params = [user_filter]

	impersonated_rows = frappe.db.sql(
		f"""
		SELECT target_user AS user, COUNT(*) AS cnt
		FROM `tabProRnd Admin Access Log`
		WHERE event_type = 'Impersonate' AND timestamp BETWEEN %s AND %s AND target_user IS NOT NULL {target_cond}
		GROUP BY target_user
		""",
		[date_from, date_to] + target_params,
		as_dict=True,
	)

	admin_actor_rows = frappe.db.sql(
		f"""
		SELECT user,
		       COUNT(*) AS total,
		       SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed
		FROM `tabProRnd Admin Access Log`
		WHERE timestamp BETWEEN %s AND %s {user_cond}
		GROUP BY user
		""",
		[date_from, date_to] + user_params,
		as_dict=True,
	)

	profiles = {}

	def bucket(u):
		return profiles.setdefault(u, {
			"user": u, "logins": 0, "failed_logins": 0, "off_hours_logins": 0,
			"distinct_ips": 0, "impersonated_count": 0, "admin_total": 0, "admin_failed": 0,
		})

	for r in login_rows:
		if not r.user:
			continue
		p = bucket(r.user)
		p["logins"] = cint(r.success)
		p["failed_logins"] = cint(r.failed)
		p["off_hours_logins"] = cint(r.off_hours)

	for r in ip_rows:
		if r.user:
			bucket(r.user)["distinct_ips"] = cint(r.distinct_ips)

	for r in impersonated_rows:
		if r.user:
			bucket(r.user)["impersonated_count"] = cint(r.cnt)

	for r in admin_actor_rows:
		if r.user:
			p = bucket(r.user)
			p["admin_total"] = cint(r.total)
			p["admin_failed"] = cint(r.failed)

	results = []
	for u, p in profiles.items():
		total_logins = p["logins"] + p["failed_logins"]
		failed_ratio = p["failed_logins"] / total_logins if total_logins else 0
		off_hours_ratio = p["off_hours_logins"] / p["logins"] if p["logins"] else 0
		multi_ip_ratio = min(p["distinct_ips"] / (_MULTI_IP_USER_THRESHOLD * 2), 1) if p["distinct_ips"] else 0
		impersonated_ratio = min(p["impersonated_count"] / 2, 1) if p["impersonated_count"] else 0
		failed_admin_ratio = p["admin_failed"] / p["admin_total"] if p["admin_total"] else 0

		factors = {
			"failed_login_ratio": round(failed_ratio * _RISK_WEIGHTS["failed_login_ratio"], 1),
			"multi_ip": round(multi_ip_ratio * _RISK_WEIGHTS["multi_ip"], 1),
			"off_hours_ratio": round(off_hours_ratio * _RISK_WEIGHTS["off_hours_ratio"], 1),
			"impersonated": round(impersonated_ratio * _RISK_WEIGHTS["impersonated"], 1),
			"failed_admin_ratio": round(failed_admin_ratio * _RISK_WEIGHTS["failed_admin_ratio"], 1),
		}
		score = round(sum(factors.values()), 1)

		results.append({
			"user": u,
			"score": score,
			"band": _risk_band(score),
			"factors": factors,
			"logins": p["logins"],
			"failed_logins": p["failed_logins"],
			"off_hours_logins": p["off_hours_logins"],
			"distinct_ips": p["distinct_ips"],
			"impersonated_count": p["impersonated_count"],
		})

	results.sort(key=lambda r: r["score"], reverse=True)
	return results


@frappe.whitelist()
def get_risk_scores(date_from=None, date_to=None, band=None, start=0, page_length=25):
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)
	start, page_length = _pagination(start, page_length)

	results = _compute_risk_scores(date_from, date_to)
	if band:
		results = [r for r in results if r["band"] == band]

	full_names = {}
	users = [r["user"] for r in results]
	if users:
		for row in frappe.db.get_all("User", filters={"name": ["in", users]}, fields=["name", "full_name"]):
			full_names[row.name] = row.full_name
	for r in results:
		r["full_name"] = full_names.get(r["user"]) or r["user"]

	band_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
	for r in results:
		band_counts[r["band"]] += 1

	total = len(results)
	page = results[start:start + page_length]
	return {"rows": page, "total": total, "start": start, "page_length": page_length, "band_counts": band_counts}


# ── Anomaly detection ─────────────────────────────────────────────────────

_SEVERITY_RANK = {"critical": 3, "warning": 2, "info": 1}


@frappe.whitelist()
def get_anomalies(date_from=None, date_to=None):
	"""Unified anomaly feed combining several independent signals:
	- a user logging in from an IP they've never used before (compared
	  against their own history in the equal-length prior window, so a
	  brand-new user's first-ever login isn't flagged as anomalous)
	- users/IPs with a burst of failed logins
	- users with unusually frequent off-hours access
	- non-browser (scripted) clients hitting the admin-bypass account
	Each is independently useful; combining them here gives one prioritized
	worklist instead of five different tabs to cross-reference."""
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)

	anomalies = []

	# Reuse the per-user profile already computed for risk scoring.
	profiles = _compute_risk_scores(date_from, date_to)
	full_names = {}
	users = [p["user"] for p in profiles]
	if users:
		for row in frappe.db.get_all("User", filters={"name": ["in", users]}, fields=["name", "full_name"]):
			full_names[row.name] = row.full_name

	for p in profiles:
		label = full_names.get(p["user"]) or p["user"]
		if p["off_hours_logins"] >= _ANOMALY_OFF_HOURS_THRESHOLD:
			anomalies.append({
				"type": "Off-hours access pattern", "severity": "info",
				"subject_type": "user", "subject": p["user"], "subject_label": label,
				"description": f"{p['off_hours_logins']} logins outside {_BUSINESS_HOUR_START}:00-{_BUSINESS_HOUR_END}:00",
				"count": p["off_hours_logins"], "timestamp": date_to,
			})
		if p["failed_logins"] >= _ANOMALY_FAILED_BURST_THRESHOLD:
			anomalies.append({
				"type": "Repeated failed logins", "severity": "critical" if p["failed_logins"] >= 10 else "warning",
				"subject_type": "user", "subject": p["user"], "subject_label": label,
				"description": f"{p['failed_logins']} failed login attempts in range",
				"count": p["failed_logins"], "timestamp": date_to,
			})

	# Failed-login burst per IP (independent of which user(s) it hit).
	ip_bursts = frappe.db.sql(
		f"""
		SELECT ip_address, COUNT(*) AS cnt, MAX(communication_date) AS last_seen
		FROM `tabActivity Log`
		WHERE operation = 'Login' AND status = 'Failed' AND communication_date BETWEEN %s AND %s
		  AND ip_address IS NOT NULL AND ip_address != ''
		GROUP BY ip_address
		HAVING cnt >= {_ANOMALY_FAILED_BURST_THRESHOLD}
		""",
		[date_from, date_to],
		as_dict=True,
	)
	for r in ip_bursts:
		anomalies.append({
			"type": "Repeated failures from one IP", "severity": "critical" if r.cnt >= 10 else "warning",
			"subject_type": "ip", "subject": r.ip_address, "subject_label": r.ip_address,
			"description": f"{r.cnt} failed login attempts from this address",
			"count": cint(r.cnt), "timestamp": str(r.last_seen),
		})

	# New IP for an established user: present now, absent in the equal-length
	# prior window, but the user DID have activity back then (otherwise this
	# is just a new user's first login, not an anomaly).
	range_days = max(1, (get_datetime(date_to).date() - get_datetime(date_from).date()).days)
	prev_to = get_datetime(date_from).date()
	prev_from = get_datetime(add_days(str(prev_to), -range_days)).date()
	prev_bounds = [f"{prev_from} 00:00:00", f"{prev_to} 23:59:59"]

	current_pairs = frappe.db.sql(
		f"""
		SELECT DISTINCT user, ip_address FROM `tabActivity Log`
		WHERE communication_date BETWEEN %s AND %s AND user NOT IN ('', 'Guest')
		  AND ip_address IS NOT NULL AND ip_address != '' AND ip_address NOT IN {_LOOPBACK_IPS_SQL}
		""",
		[date_from, date_to],
		as_dict=True,
	)
	prior_pairs = frappe.db.sql(
		f"""
		SELECT DISTINCT user, ip_address FROM `tabActivity Log`
		WHERE communication_date BETWEEN %s AND %s AND user NOT IN ('', 'Guest')
		  AND ip_address IS NOT NULL AND ip_address != '' AND ip_address NOT IN {_LOOPBACK_IPS_SQL}
		""",
		prev_bounds,
		as_dict=True,
	)
	prior_users = set()
	prior_user_ips = {}
	for r in prior_pairs:
		prior_users.add(r.user)
		prior_user_ips.setdefault(r.user, set()).add(r.ip_address)

	for r in current_pairs:
		if r.user in prior_users and r.ip_address not in prior_user_ips.get(r.user, set()):
			anomalies.append({
				"type": "New IP for established user", "severity": "warning",
				"subject_type": "user", "subject": r.user, "subject_label": full_names.get(r.user) or r.user,
				"description": f"First seen logging in from {r.ip_address}",
				"count": 1, "timestamp": date_to,
			})

	# Scripted/non-browser clients hitting the admin-bypass account.
	device_data = get_device_analysis(date_from, date_to)
	for s in device_data["scripts"]:
		anomalies.append({
			"type": "Non-browser client detected", "severity": "critical",
			"subject_type": "user", "subject": (s["users"][0] if s["users"] else None), "subject_label": ", ".join(s["users"]) or "unknown",
			"description": f"{s['count']} request(s) via {s['client']} (script/API client, not a browser)",
			"count": s["count"], "timestamp": s["last_seen"],
		})

	anomalies.sort(key=lambda a: (_SEVERITY_RANK.get(a["severity"], 0), a["count"]), reverse=True)
	return {"anomalies": anomalies[:200], "total": len(anomalies)}

# ── Genuine (non-impersonated) logins ────────────────────────────────────
#
# When prorndadmin impersonates a user, Frappe's LoginManager.impersonate()
# writes a normal 'Login' Activity Log row for the TARGET user at the moment
# the session is swapped — carrying prorndadmin's real IP, not the target
# user's. Left uncorrected, that makes it look like every impersonated user
# logged in from prorndadmin's workstation. These helpers cross-reference
# ProRnd Admin Access Log's Impersonate events to strip that noise out and
# recover a best-effort "this person really logged in from this machine"
# mapping.

_IMPERSONATION_MATCH_TOLERANCE_SECONDS = 5


def _impersonation_timestamps(date_from, date_to):
	"""user -> sorted list of datetimes when they were the TARGET of a
	successful impersonation, padded a day either side of the range so
	matches near the boundary aren't missed."""
	pad_from = add_days(date_from.split(" ")[0], -1) + " 00:00:00"
	pad_to = add_days(date_to.split(" ")[0], 1) + " 23:59:59"
	rows = frappe.db.sql(
		"""
		SELECT target_user, timestamp FROM `tabProRnd Admin Access Log`
		WHERE event_type = 'Impersonate' AND status = 'Success'
		  AND target_user IS NOT NULL AND target_user != ''
		  AND timestamp BETWEEN %s AND %s
		""",
		[pad_from, pad_to],
		as_dict=True,
	)
	out = {}
	for r in rows:
		out.setdefault(r.target_user, []).append(get_datetime(r.timestamp))
	for user in out:
		out[user].sort()
	return out


def _is_impersonation_artifact(ts, candidates):
	if not candidates:
		return False
	return any(abs((ts - c).total_seconds()) <= _IMPERSONATION_MATCH_TOLERANCE_SECONDS for c in candidates)


@frappe.whitelist()
def get_genuine_user_ips(date_from=None, date_to=None, user=None, start=0, page_length=25):
	"""Per-user breakdown of real login IPs, with impersonation artifacts and
	unresolved/loopback addresses split out rather than counted as real
	activity. `primary_ip` is the address each user logged in from most often
	— the closest thing this data gives to "their machine"."""
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)

	al_cond = "operation = 'Login' AND status = 'Success' AND communication_date BETWEEN %s AND %s AND user NOT IN ('', 'Guest')"
	al_params = [date_from, date_to]
	if user:
		al_cond += " AND user = %s"
		al_params.append(user)

	logins = frappe.db.sql(
		f"""
		SELECT user, communication_date AS ts, ip_address
		FROM `tabActivity Log`
		WHERE {al_cond}
		""",
		al_params,
		as_dict=True,
	)

	imp_map = _impersonation_timestamps(date_from, date_to)

	stats = {}
	for r in logins:
		e = stats.setdefault(r.user, {
			"user": r.user, "total_logins": 0, "genuine_logins": 0,
			"impersonated_logins": 0, "unresolved_logins": 0, "ips": {},
		})
		e["total_logins"] += 1
		ts = get_datetime(r.ts)
		if _is_impersonation_artifact(ts, imp_map.get(r.user)):
			e["impersonated_logins"] += 1
			continue
		ip = r.ip_address
		if not ip or ip in _LOOPBACK_IPS:
			e["unresolved_logins"] += 1
			continue
		e["genuine_logins"] += 1
		ip_entry = e["ips"].setdefault(ip, {"ip_address": ip, "count": 0, "last_seen": None})
		ip_entry["count"] += 1
		if not ip_entry["last_seen"] or str(r.ts) > str(ip_entry["last_seen"]):
			ip_entry["last_seen"] = str(r.ts)

	full_names = {}
	if stats:
		for row in frappe.db.get_all("User", filters={"name": ["in", list(stats.keys())]}, fields=["name", "full_name"]):
			full_names[row.name] = row.full_name

	result = []
	for u, e in stats.items():
		ip_list = sorted(e["ips"].values(), key=lambda r: r["count"], reverse=True)
		primary = ip_list[0] if ip_list else None
		result.append({
			"user": u,
			"full_name": full_names.get(u) or u,
			"total_logins": e["total_logins"],
			"genuine_logins": e["genuine_logins"],
			"impersonated_logins": e["impersonated_logins"],
			"unresolved_logins": e["unresolved_logins"],
			"distinct_genuine_ips": len(ip_list),
			"primary_ip": primary["ip_address"] if primary else None,
			"primary_ip_count": primary["count"] if primary else 0,
			"primary_ip_last_seen": primary["last_seen"] if primary else None,
			"all_ips": ip_list,
		})

	# Users with a real, attributable IP first (ranked by volume); accounts
	# that only ever show up as impersonation targets or via unresolved
	# addresses — never a genuine direct login — sort to the bottom.
	result.sort(key=lambda r: (-r["genuine_logins"], -r["total_logins"]))

	summary = {
		"users_with_genuine_ip": sum(1 for r in result if r["genuine_logins"] > 0),
		"users_impersonation_only": sum(1 for r in result if r["genuine_logins"] == 0 and r["impersonated_logins"] > 0),
		"users_unresolved_only": sum(1 for r in result if r["genuine_logins"] == 0 and r["impersonated_logins"] == 0 and r["unresolved_logins"] > 0),
		"total_genuine_logins": sum(r["genuine_logins"] for r in result),
		"total_impersonated_logins": sum(r["impersonated_logins"] for r in result),
		"total_unresolved_logins": sum(r["unresolved_logins"] for r in result),
	}

	total = len(result)
	start, page_length = _pagination(start, page_length)
	page = result[start:start + page_length]

	return {
		"rows": page, "total": total, "start": start, "page_length": page_length,
		"tolerance_seconds": _IMPERSONATION_MATCH_TOLERANCE_SECONDS,
		"summary": summary,
	}


# ── Security event timeline ──────────────────────────────────────────────

@frappe.whitelist()
def get_security_timeline(date_from=None, date_to=None, user=None, ip=None, severity=None, start=0, page_length=30):
	"""Curated, severity-tagged feed of only the security-relevant events —
	failed logins, impersonation, admin-bypass usage, off-hours access —
	as opposed to Recent Audit Logs, which is the unfiltered raw firehose."""
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)
	start, page_length = _pagination(start, page_length)
	fetch_n = start + page_length

	events = []

	al_cond = "operation = 'Login' AND communication_date BETWEEN %s AND %s"
	al_params = [date_from, date_to]
	if user:
		al_cond += " AND user = %s"
		al_params.append(user)
	if ip:
		al_cond += " AND ip_address = %s"
		al_params.append(ip)

	for r in frappe.db.sql(
		f"""
		SELECT user, full_name, status, communication_date AS ts, ip_address, subject
		FROM `tabActivity Log`
		WHERE {al_cond}
		ORDER BY communication_date DESC
		LIMIT {fetch_n}
		""",
		al_params,
		as_dict=True,
	):
		if r.status == "Failed":
			sev, etype = "warning", "Failed login"
		elif get_datetime(r.ts).hour < _BUSINESS_HOUR_START or get_datetime(r.ts).hour >= _BUSINESS_HOUR_END:
			sev, etype = "info", "Off-hours login"
		else:
			continue  # ordinary successful business-hours login isn't timeline-worthy
		events.append({
			"severity": sev, "type": etype, "timestamp": str(r.ts), "user": r.user or "",
			"detail": r.subject, "ip_address": r.ip_address, "source": "Activity Log",
		})

	pal_cond = "timestamp BETWEEN %s AND %s"
	pal_params = [date_from, date_to]
	if user:
		pal_cond += " AND user = %s"
		pal_params.append(user)
	if ip:
		pal_cond += " AND ip_address = %s"
		pal_params.append(ip)

	for r in frappe.db.sql(
		f"""
		SELECT user, target_user, event_type, status, timestamp AS ts, ip_address, details
		FROM `tabProRnd Admin Access Log`
		WHERE {pal_cond} AND event_type IN ('Login', 'Impersonate')
		ORDER BY timestamp DESC
		LIMIT {fetch_n}
		""",
		pal_params,
		as_dict=True,
	):
		if r.event_type == "Login" and r.status == "Failed":
			sev, etype = "critical", "Failed admin-bypass login"
		elif r.event_type == "Login":
			sev, etype = "warning", "Admin-bypass login"
		else:
			sev, etype = "warning", "Impersonation started"
		events.append({
			"severity": sev, "type": etype, "timestamp": str(r.ts), "user": r.user or "",
			"detail": r.details or (f"target: {r.target_user}" if r.target_user else ""),
			"ip_address": r.ip_address, "source": "Admin Access Log",
		})

	if severity:
		events = [e for e in events if e["severity"] == severity]

	events.sort(key=lambda e: e["timestamp"], reverse=True)
	page = events[start:start + page_length]
	return {"rows": page, "start": start, "page_length": page_length, "has_more": len(events) > start + page_length}


# ── Actionable recommendations ───────────────────────────────────────────

@frappe.whitelist()
def get_recommendations(date_from=None, date_to=None):
	"""Deterministic, rule-based recommendations derived from the same
	aggregates the rest of the dashboard already computes — intentionally
	not ML-based, so every recommendation traces back to a concrete number."""
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)

	recs = []

	kpis = get_kpis(date_from, date_to)
	total_logins = kpis["successful_logins"] + kpis["failed_logins"]
	failed_ratio = (kpis["failed_logins"] / total_logins * 100) if total_logins else 0

	if failed_ratio >= 5:
		recs.append({
			"severity": "critical" if failed_ratio >= 15 else "warning",
			"title": "Elevated failed-login rate",
			"detail": f"{kpis['failed_logins']} of {total_logins} login attempts failed ({failed_ratio:.1f}%). "
			          f"Review the Failed & Suspicious tab and consider tightening lockout policy.",
		})

	if kpis["suspicious_ip_count"]:
		recs.append({
			"severity": "critical",
			"title": "IP addresses with repeated failed logins",
			"detail": f"{kpis['suspicious_ip_count']} IP address(es) have 3+ failed login attempts in range — "
			          f"candidates for blocking or investigation. See the IP Address Activity tab.",
		})

	if kpis["off_hours_logins"]:
		recs.append({
			"severity": "info",
			"title": "Off-hours access observed",
			"detail": f"{kpis['off_hours_logins']} successful logins occurred outside "
			          f"{_BUSINESS_HOUR_START}:00-{_BUSINESS_HOUR_END}:00. Confirm this matches expected work patterns.",
		})

	ip_insights = get_ip_insights(date_from, date_to)
	if ip_insights["shared_ips"]:
		top = ip_insights["shared_ips"][0]
		recs.append({
			"severity": "warning",
			"title": "Shared IP addresses in use",
			"detail": f"{len(ip_insights['shared_ips'])} IP address(es) are used by {ip_insights['shared_ip_threshold']}+ "
			          f"distinct users each (top: {top['ip_address']} with {top['distinct_users']} users). "
			          f"Verify these are legitimate shared workstations.",
		})

	if ip_insights["new_ips"]:
		recs.append({
			"severity": "info",
			"title": "New IP addresses first seen this period",
			"detail": f"{len(ip_insights['new_ips'])} IP address(es) were not seen in the prior equal-length window. "
			          f"Review the New / First-seen IPs panel for anything unexpected.",
		})

	risk = get_risk_scores(date_from, date_to, page_length=1)
	critical_count = risk["band_counts"].get("Critical", 0)
	high_count = risk["band_counts"].get("High", 0)
	if critical_count or high_count:
		recs.append({
			"severity": "critical" if critical_count else "warning",
			"title": "Users flagged by risk scoring",
			"detail": f"{critical_count} user(s) scored Critical and {high_count} scored High risk "
			          f"(failed logins, off-hours access, multi-IP use, or impersonation exposure). "
			          f"See the Risk Scoring tab for the ranked list and contributing factors.",
		})

	device_data = get_device_analysis(date_from, date_to)
	if device_data["scripts"]:
		recs.append({
			"severity": "critical",
			"title": "Non-browser clients detected on the admin-bypass account",
			"detail": f"{sum(s['count'] for s in device_data['scripts'])} request(s) came from scripted/API "
			          f"clients (curl, Python, Postman) rather than a browser — confirm these are authorized integrations.",
		})

	if kpis["impersonation_sessions"]:
		recs.append({
			"severity": "info",
			"title": "Admin impersonation activity",
			"detail": f"{kpis['impersonation_sessions']} impersonation session(s) were initiated via the admin-bypass "
			          f"account in range. Periodically audit these against expected support activity.",
		})

	if not recs:
		recs.append({
			"severity": "info",
			"title": "No significant issues detected",
			"detail": "No elevated failure rates, flagged IPs, or high-risk users were found for this range.",
		})

	recs.sort(key=lambda r: _SEVERITY_RANK.get(r["severity"], 0), reverse=True)
	return {"recommendations": recs}


# ── User detail drill-down ────────────────────────────────────────────────

@frappe.whitelist()
def get_user_detail(user, date_from=None, date_to=None):
	"""Drill-down for a single user: risk profile, IPs used, module activity,
	and recent events — the user-centric counterpart to get_ip_detail."""
	_ensure_access()
	if not user:
		frappe.throw(frappe._("user is required"))
	date_from, date_to = _date_bounds(date_from, date_to)

	profile = _compute_risk_scores(date_from, date_to, user_filter=user)
	risk = profile[0] if profile else {
		"user": user, "score": 0, "band": "Low", "factors": {k: 0 for k in _RISK_WEIGHTS},
		"logins": 0, "failed_logins": 0, "off_hours_logins": 0, "distinct_ips": 0, "impersonated_count": 0,
	}

	full_name = frappe.db.get_value("User", user, "full_name") or user

	ip_rows = frappe.db.sql(
		"""
		SELECT ip_address,
		       COUNT(*) AS total,
		       SUM(CASE WHEN status = 'Success' THEN 1 ELSE 0 END) AS success,
		       SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed,
		       MIN(communication_date) AS first_seen,
		       MAX(communication_date) AS last_seen
		FROM `tabActivity Log`
		WHERE user = %s AND communication_date BETWEEN %s AND %s
		  AND ip_address IS NOT NULL AND ip_address != ''
		GROUP BY ip_address
		ORDER BY total DESC
		""",
		[user, date_from, date_to],
		as_dict=True,
	)
	for r in ip_rows:
		r["is_internal"] = r.ip_address in _LOOPBACK_IPS

	module_rows = frappe.db.sql(
		"""
		SELECT COALESCE(NULLIF(form_category, ''), 'Other') AS module, COUNT(*) AS cnt
		FROM `tabStaff Activity Log`
		WHERE user = %s AND timestamp BETWEEN %s AND %s
		GROUP BY module
		ORDER BY cnt DESC
		""",
		[user, date_from, date_to],
		as_dict=True,
	)

	events = []
	for r in frappe.db.sql(
		"""
		SELECT operation, status, communication_date AS ts, ip_address, subject
		FROM `tabActivity Log`
		WHERE user = %s AND communication_date BETWEEN %s AND %s
		ORDER BY communication_date DESC
		LIMIT 100
		""",
		[user, date_from, date_to],
		as_dict=True,
	):
		events.append({
			"source": "Activity Log", "timestamp": str(r.ts), "event": r.operation or "Login",
			"status": r.status, "detail": r.subject, "ip_address": r.ip_address,
		})
	for r in frappe.db.sql(
		"""
		SELECT event_type, target_user, status, timestamp AS ts, ip_address, details
		FROM `tabProRnd Admin Access Log`
		WHERE user = %s AND timestamp BETWEEN %s AND %s
		ORDER BY timestamp DESC
		LIMIT 100
		""",
		[user, date_from, date_to],
		as_dict=True,
	):
		events.append({
			"source": "Admin Access Log", "timestamp": str(r.ts), "event": r.event_type,
			"status": r.status, "detail": r.details or (f"target: {r.target_user}" if r.target_user else ""),
			"ip_address": r.ip_address,
		})
	for r in frappe.db.sql(
		"""
		SELECT doctype_name, document_name, action, form_category, timestamp AS ts
		FROM `tabStaff Activity Log`
		WHERE user = %s AND timestamp BETWEEN %s AND %s
		ORDER BY timestamp DESC
		LIMIT 100
		""",
		[user, date_from, date_to],
		as_dict=True,
	):
		events.append({
			"source": "Staff Activity Log", "timestamp": str(r.ts), "event": r.action or "Workflow Action",
			"status": None, "detail": f"{r.doctype_name} {r.document_name} ({r.form_category or 'Other'})",
			"ip_address": None,
		})

	events.sort(key=lambda e: e["timestamp"], reverse=True)

	return {
		"user": user,
		"full_name": full_name,
		"risk": risk,
		"ip_breakdown": ip_rows,
		"module_breakdown": module_rows,
		"events": events[:100],
	}


# ── Unresolved-IP prediction ─────────────────────────────────────────────
#
# Cross-checking against get_genuine_user_ips surfaced a bigger finding than
# impersonation noise: IP resolution was 100% broken (every Login/Logout row
# = loopback/blank) for this entire log's history up to 2026-07-27, then
# started working from 2026-07-28 onward. So "predicting" an unresolved
# login's IP can't lean on nearby-in-time evidence for most of the data —
# there isn't any. The only honest signal available is a user's OWN resolved
# IP(s), wherever in their history those happen to fall (typically only the
# last day or two). No cross-user inference is attempted: guessing someone's
# IP from a colleague's, even one on the same office subnet, would be
# fabricating attribution in a security audit tool, not predicting it.

@frappe.whitelist()
def get_unresolved_ip_predictions(date_from=None, date_to=None, user=None, start=0, page_length=25):
	"""For each user with unresolved (loopback/blank IP) logins in range,
	predict their most likely real IP from their own genuine login history —
	searched across all time, not just the selected range, since resolvable
	IPs are concentrated in a narrow recent window for almost everyone."""
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)

	al_cond = "operation = 'Login' AND status = 'Success' AND communication_date BETWEEN %s AND %s AND user NOT IN ('', 'Guest')"
	al_params = [date_from, date_to]
	if user:
		al_cond += " AND user = %s"
		al_params.append(user)

	logins = frappe.db.sql(
		f"SELECT user, communication_date AS ts, ip_address FROM `tabActivity Log` WHERE {al_cond}",
		al_params,
		as_dict=True,
	)

	imp_map = _impersonation_timestamps(date_from, date_to)

	unresolved = {}
	for r in logins:
		ts = get_datetime(r.ts)
		if _is_impersonation_artifact(ts, imp_map.get(r.user)):
			continue
		ip = r.ip_address
		if ip and ip not in _LOOPBACK_IPS:
			continue
		e = unresolved.setdefault(r.user, {"count": 0, "last_seen": None})
		e["count"] += 1
		if not e["last_seen"] or str(r.ts) > str(e["last_seen"]):
			e["last_seen"] = str(r.ts)

	unresolved_users = list(unresolved.keys())
	unresolved_logins_total = sum(e["count"] for e in unresolved.values())

	if not unresolved_users:
		return {
			"rows": [], "total": 0, "start": 0, "page_length": _DEFAULT_PAGE_LENGTH,
			"summary": {
				"unresolved_users": 0, "unresolved_logins": 0,
				"predictable_users": 0, "unpredictable_users": 0,
			},
		}

	# Reference: this user's own resolved IPs, at any point in their history
	# up to the end of the selected range — deliberately not bounded to
	# date_from, since almost all resolved data sits in the last couple of
	# days regardless of what range is selected.
	imp_map_all = _impersonation_timestamps("2000-01-01 00:00:00", date_to)
	ref_rows = frappe.db.sql(
		f"""
		SELECT user, ip_address, communication_date AS ts
		FROM `tabActivity Log`
		WHERE operation = 'Login' AND status = 'Success'
		  AND communication_date <= %s
		  AND ip_address IS NOT NULL AND ip_address != ''
		  AND user IN ({", ".join(["%s"] * len(unresolved_users))})
		""",
		[date_to] + unresolved_users,
		as_dict=True,
	)

	genuine_ip_counts = {}
	for r in ref_rows:
		if r.ip_address in _LOOPBACK_IPS:
			continue
		ts = get_datetime(r.ts)
		if _is_impersonation_artifact(ts, imp_map_all.get(r.user)):
			continue
		bucket = genuine_ip_counts.setdefault(r.user, {})
		e = bucket.setdefault(r.ip_address, {"ip_address": r.ip_address, "count": 0, "last_seen": None})
		e["count"] += 1
		if not e["last_seen"] or str(r.ts) > str(e["last_seen"]):
			e["last_seen"] = str(r.ts)

	full_names = {}
	for row in frappe.db.get_all("User", filters={"name": ["in", unresolved_users]}, fields=["name", "full_name"]):
		full_names[row.name] = row.full_name

	result = []
	for u, e in unresolved.items():
		ip_list = sorted(genuine_ip_counts.get(u, {}).values(), key=lambda r: r["count"], reverse=True)
		predicted = ip_list[0] if ip_list else None
		total_ref = sum(i["count"] for i in ip_list)
		confidence = round(predicted["count"] / total_ref * 100) if predicted and total_ref else 0
		result.append({
			"user": u,
			"full_name": full_names.get(u) or u,
			"unresolved_logins": e["count"],
			"last_unresolved": e["last_seen"],
			"predicted_ip": predicted["ip_address"] if predicted else None,
			"predicted_ip_confidence": confidence,
			"predicted_ip_observations": predicted["count"] if predicted else 0,
			"predicted_ip_last_seen": predicted["last_seen"] if predicted else None,
			"alt_ip_count": max(0, len(ip_list) - 1),
		})

	# Predictable users first (most unresolved activity first within that
	# group), then users we genuinely have no evidence for.
	result.sort(key=lambda r: (r["predicted_ip"] is None, -r["unresolved_logins"]))

	predictable_users = sum(1 for r in result if r["predicted_ip"])
	summary = {
		"unresolved_users": len(result),
		"unresolved_logins": unresolved_logins_total,
		"predictable_users": predictable_users,
		"unpredictable_users": len(result) - predictable_users,
	}

	total = len(result)
	start, page_length = _pagination(start, page_length)
	page = result[start:start + page_length]

	return {"rows": page, "total": total, "start": start, "page_length": page_length, "summary": summary}


# ── Document change history (field-level, IP-attributed) ────────────────
#
# Frappe's own Version doctype already records every field-level edit on
# every tracked-changes doctype in the system — but it doesn't record an IP.
# This cross-references each edit's editor against their own Login/Logout
# Activity Log entries to find the session bracketing that edit, and reports
# the IP that session used — the same manual technique used to trace who
# changed rndadmin's Role Profile and from where.

_EDITOR_IP_WINDOW_HOURS = 12


def _resolve_editor_ip(user, ts):
	"""Best-effort session IP for `user` at time `ts`: the nearest Login or
	Logout Activity Log entry for that user within a trailing/leading window.
	Not authoritative — a save can happen anywhere inside a long session, so
	this is the closest boundary evidence available, not a guarantee."""
	if not user or not ts:
		return {"ip_address": None, "is_internal": False, "method": None, "gap_seconds": None}

	ts = get_datetime(ts)
	window_start = ts - timedelta(hours=_EDITOR_IP_WINDOW_HOURS)
	window_end = ts + timedelta(hours=_EDITOR_IP_WINDOW_HOURS)

	rows = frappe.db.sql(
		"""
		SELECT operation, communication_date AS cd, ip_address
		FROM `tabActivity Log`
		WHERE user = %s AND operation IN ('Login', 'Logout') AND status = 'Success'
		  AND communication_date BETWEEN %s AND %s
		  AND ip_address IS NOT NULL AND ip_address != ''
		ORDER BY communication_date ASC
		""",
		[user, window_start, window_end],
		as_dict=True,
	)

	best, best_gap = None, None
	for r in rows:
		gap = abs((get_datetime(r.cd) - ts).total_seconds())
		if best_gap is None or gap < best_gap:
			best, best_gap = r, gap

	if not best:
		return {"ip_address": None, "is_internal": False, "method": None, "gap_seconds": None}

	return {
		"ip_address": best.ip_address,
		"is_internal": best.ip_address in _LOOPBACK_IPS,
		"method": f"nearest {best.operation.lower()} ({str(best.cd)})",
		"gap_seconds": round(best_gap),
	}


@frappe.whitelist()
def get_document_changes(doctype=None, docname=None, user=None, date_from=None, date_to=None, start=0, page_length=25):
	"""Field-level edit history across any doctype in the system, each row
	attributed to the editor's best-guess session IP."""
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)
	start, page_length = _pagination(start, page_length)

	cond = "creation BETWEEN %s AND %s"
	params = [date_from, date_to]
	if doctype:
		cond += " AND ref_doctype = %s"
		params.append(doctype)
	if docname:
		cond += " AND docname LIKE %s"
		params.append(f"%{docname}%")
	if user:
		cond += " AND owner = %s"
		params.append(user)

	total = frappe.db.sql(f"SELECT COUNT(*) FROM `tabVersion` WHERE {cond}", params)[0][0]

	rows = frappe.db.sql(
		f"""
		SELECT name, ref_doctype, docname, owner, creation, data
		FROM `tabVersion`
		WHERE {cond}
		ORDER BY creation DESC
		LIMIT %s OFFSET %s
		""",
		params + [page_length, start],
		as_dict=True,
	)

	full_names = {}
	owners = list({r.owner for r in rows if r.owner})
	if owners:
		for u in frappe.db.get_all("User", filters={"name": ["in", owners]}, fields=["name", "full_name"]):
			full_names[u.name] = u.full_name

	results = []
	for r in rows:
		try:
			data = json.loads(r.data) if r.data else {}
		except Exception:
			data = {}
		changed = [
			{"field": c[0], "old": c[1], "new": c[2]}
			for c in (data.get("changed") or [])
			if len(c) >= 3
		]

		ip_info = _resolve_editor_ip(r.owner, r.creation)
		results.append({
			"name": r.name,
			"doctype": r.ref_doctype,
			"docname": r.docname,
			"editor": r.owner,
			"editor_full_name": full_names.get(r.owner) or r.owner,
			"timestamp": str(r.creation),
			"changes": changed,
			"ip_address": ip_info["ip_address"],
			"ip_is_internal": ip_info["is_internal"],
			"ip_method": ip_info["method"],
			"ip_gap_seconds": ip_info["gap_seconds"],
		})

	return {"rows": results, "total": cint(total), "start": start, "page_length": page_length}


@frappe.whitelist()
def get_changed_doctypes(date_from=None, date_to=None):
	"""Distinct doctypes with edits in range, for the Document Changes tab's
	doctype filter — built from what's actually in the data rather than a
	hardcoded list, so it stays correct as new doctypes get edited."""
	_ensure_access()
	date_from, date_to = _date_bounds(date_from, date_to)

	rows = frappe.db.sql(
		"""
		SELECT ref_doctype, COUNT(*) AS cnt
		FROM `tabVersion`
		WHERE creation BETWEEN %s AND %s
		GROUP BY ref_doctype
		ORDER BY cnt DESC
		LIMIT 100
		""",
		[date_from, date_to],
		as_dict=True,
	)
	return [{"doctype": r.ref_doctype, "count": cint(r.cnt)} for r in rows]
