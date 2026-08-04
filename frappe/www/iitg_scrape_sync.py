"""
Web page + API backend for syncing IITG faculty / department-head data
(scraped from iitg.ac.in via kafka_control.py) into the system's User and
Department_prornd records.

Flow:
  1. An admin (System Manager) triggers a scrape ("faculty" or
     "department_heads") from the page. It runs as a background job because
     a full site crawl can take several minutes.
  2. The page polls job status, then fetches the raw scraped rows and a
     comparison against the current User / Department_prornd data.
  3. For rows that differ, the admin can manually push the scraped name/
     email into the system with a per-row "Update" action. Updating a
     User's details is only allowed when that User currently holds the
     "Permanent Employee" role.

Scrape results are cached in Redis (frappe.cache) rather than a doctype --
this is a lightweight sync utility, not a system of record.
"""

import re

import frappe
from frappe import _

from frappe.www.kafka_control import (
	collect_department_heads,
	collect_faculty_from_departments,
	discover_department_slugs,
	enrich_with_profile_pages,
)

no_cache = 1

SCRAPE_TYPES = ("faculty", "department_heads")
CACHE_TTL = 6 * 60 * 60  # 6 hours
PERMANENT_EMPLOYEE_ROLE = "Permanent Employee"


def get_context(context):
	# Guests are redirected to /login client-side (see iitg_scrape_sync.html);
	# every whitelisted method below independently enforces System Manager.
	context.no_cache = 1
	return context


# ---------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------

def _require_system_manager():
	if "System Manager" not in frappe.get_roles():
		frappe.throw(_("Only a System Manager can perform this action."), frappe.PermissionError)


def _validate_scrape_type(scrape_type):
	if scrape_type not in SCRAPE_TYPES:
		frappe.throw(_("Invalid scrape type: {0}").format(scrape_type))


def _status_key(scrape_type):
	return f"iitg_scrape:status:{scrape_type}"


def _data_key(scrape_type):
	return f"iitg_scrape:data:{scrape_type}"


def _set_status(scrape_type, **kwargs):
	key = _status_key(scrape_type)
	status = frappe.cache().get_value(key) or {}
	status.update(kwargs)
	frappe.cache().set_value(key, status, expires_in_sec=CACHE_TTL)
	return status


def _normalize_dept_name(name):
	name = (name or "").lower().strip()
	for prefix in ("department of ", "school of ", "centre for ", "center for "):
		if name.startswith(prefix):
			name = name[len(prefix):]
			break
	name = re.sub(r"\s*&\s*", " and ", name)
	return " ".join(name.split())


# ---------------------------------------------------------------------
# scrape trigger + status
# ---------------------------------------------------------------------

@frappe.whitelist()
def start_scrape(scrape_type, departments=None):
	_require_system_manager()
	_validate_scrape_type(scrape_type)

	existing = frappe.cache().get_value(_status_key(scrape_type))
	if existing and existing.get("state") == "running":
		frappe.throw(
			_("A {0} scrape is already running (started by {1}).").format(
				scrape_type, existing.get("started_by")
			)
		)

	dept_list = None
	if departments:
		dept_list = [d.strip() for d in departments.split(",") if d.strip()]

	_set_status(
		scrape_type,
		state="running",
		started_by=frappe.session.user,
		started_at=frappe.utils.now(),
		finished_at=None,
		error=None,
		count=0,
	)

	frappe.enqueue(
		method="frappe.www.iitg_scrape_sync.run_scrape_job",
		queue="long",
		timeout=1800,
		job_name=f"iitg_scrape_{scrape_type}",
		scrape_type=scrape_type,
		departments=dept_list,
	)
	return {"ok": True}


def run_scrape_job(scrape_type, departments=None):
	"""Runs in a background worker -- see start_scrape()."""
	try:
		_set_status(scrape_type, progress={"stage": "Discovering departments", "done": 0, "total": 0})
		slugs = departments or discover_department_slugs()
		if not slugs:
			raise RuntimeError("No department slugs discovered/given.")

		if scrape_type == "department_heads":
			def on_progress(done, total):
				_set_status(scrape_type, progress={"stage": "Scraping departments", "done": done, "total": total})

			heads = collect_department_heads(slugs, on_progress=on_progress)
			rows = [
				{
					"slug": h["slug"],
					"section": h["section"],
					"department": h["department"],
					"fac_id": h["fac_id"],
					"name": h["name"],
					"designation": h["designation"],
					"phone": h["phone"],
					"email": h["email"],
				}
				for h in heads
			]
		else:
			def on_collect_progress(done, total):
				_set_status(scrape_type, progress={"stage": "Scraping department listings", "done": done, "total": total})

			faculty_map = collect_faculty_from_departments(slugs, on_progress=on_collect_progress)

			def on_enrich_progress(done, total):
				_set_status(scrape_type, progress={"stage": "Fetching faculty profiles", "done": done, "total": total})

			enrich_with_profile_pages(faculty_map, workers=8, on_progress=on_enrich_progress)
			rows = [
				{
					"fac_id": fac_id,
					"name": r["name"],
					"email": r["email"],
					"section": r["section"],
					"department": r["department"],
					"designation": r["designation"],
				}
				for fac_id, r in faculty_map.items()
			]
		rows.sort(key=lambda r: (r.get("section") or "", r.get("department") or "", r.get("name") or ""))

		frappe.cache().set_value(_data_key(scrape_type), rows, expires_in_sec=CACHE_TTL)
		_set_status(
			scrape_type,
			state="done",
			finished_at=frappe.utils.now(),
			count=len(rows),
			error=None,
			progress={"stage": "Done", "done": len(rows), "total": len(rows)},
		)
	except Exception:
		frappe.log_error(title=f"IITG {scrape_type} scrape failed")
		_set_status(scrape_type, state="error", finished_at=frappe.utils.now(), error=frappe.get_traceback())


@frappe.whitelist()
def get_scrape_status(scrape_type):
	_require_system_manager()
	_validate_scrape_type(scrape_type)
	return frappe.cache().get_value(_status_key(scrape_type)) or {"state": "idle"}


# ---------------------------------------------------------------------
# comparisons
# ---------------------------------------------------------------------

@frappe.whitelist()
def get_faculty_comparison():
	"""Scraped faculty rows joined against System Users, matched by email."""
	_require_system_manager()
	rows = frappe.cache().get_value(_data_key("faculty")) or []

	emails = sorted({r["email"] for r in rows if r.get("email")})
	users = {}
	if emails:
		for u in frappe.get_all(
			"User",
			filters={"name": ["in", emails]},
			fields=["name", "full_name", "first_name", "middle_name", "last_name", "enabled"],
		):
			users[u.name] = u

	result = []
	for r in rows:
		email = r.get("email")
		user = users.get(email)
		is_permanent = bool(user) and PERMANENT_EMPLOYEE_ROLE in frappe.get_roles(email)
		name_changed = bool(user) and (user.full_name or "").strip() != (r.get("name") or "").strip()

		if not email:
			status = "no_scraped_email"
		elif not user:
			status = "no_account"
		elif name_changed:
			status = "name_changed"
		else:
			status = "match"

		result.append(
			{
				"scraped_name": r.get("name"),
				"scraped_email": email,
				"department": r.get("department"),
				"section": r.get("section"),
				"designation": r.get("designation"),
				"system_email": user.name if user else None,
				"system_full_name": user.full_name if user else None,
				"system_first_name": user.first_name if user else None,
				"system_middle_name": user.middle_name if user else None,
				"system_last_name": user.last_name if user else None,
				"system_enabled": bool(user.enabled) if user else None,
				"is_permanent_employee": is_permanent,
				"status": status,
				"can_update": status == "name_changed" and is_permanent,
			}
		)
	return result


@frappe.whitelist()
def get_permanent_employees_not_in_scrape():
	"""Reverse of get_faculty_comparison(): Permanent Employee Users the last faculty scrape
	never turned up at all (as opposed to rows scraped-but-unmatched, which the comparison
	table above already covers)."""
	_require_system_manager()

	permanent_emails = frappe.get_all(
		"Has Role", filters={"role": PERMANENT_EMPLOYEE_ROLE, "parenttype": "User"}, pluck="parent"
	)
	if not permanent_emails:
		return []

	scraped_emails = {
		r["email"] for r in (frappe.cache().get_value(_data_key("faculty")) or []) if r.get("email")
	}

	users = frappe.get_all(
		"User",
		filters={"name": ["in", permanent_emails]},
		fields=["name", "full_name", "first_name", "middle_name", "last_name", "enabled"],
		order_by="full_name asc",
	)
	return [u for u in users if u.name not in scraped_emails]


@frappe.whitelist()
def get_department_head_comparison():
	"""Scraped department-head rows joined against Department_prornd.dept_head."""
	_require_system_manager()
	rows = frappe.cache().get_value(_data_key("department_heads")) or []

	dept_records = frappe.get_all(
		"Department_prornd", fields=["name", "dept_id", "dept_name", "dept_head", "dept_initials"]
	)
	by_norm = {}
	for d in dept_records:
		by_norm.setdefault(_normalize_dept_name(d.dept_name), d)

	head_emails = sorted({d.dept_head for d in dept_records if d.dept_head})
	scraped_emails = sorted({r["email"] for r in rows if r.get("email")})
	all_user_emails = sorted(set(head_emails) | set(scraped_emails))
	users = {}
	if all_user_emails:
		for u in frappe.get_all(
			"User",
			filters={"name": ["in", all_user_emails]},
			fields=["name", "full_name", "first_name", "middle_name", "last_name"],
		):
			users[u.name] = u

	result = []
	for r in rows:
		dept = by_norm.get(_normalize_dept_name(r.get("department")))
		scraped_email = r.get("email")
		current_head_email = dept.dept_head if dept else None
		current_head = users.get(current_head_email) if current_head_email else None
		new_head_user = users.get(scraped_email) if scraped_email else None

		new_user_exists = bool(new_head_user)
		new_user_is_permanent = new_user_exists and PERMANENT_EMPLOYEE_ROLE in frappe.get_roles(scraped_email)
		email_changed = bool(scraped_email) and scraped_email != current_head_email

		if not dept:
			status = "no_department_record"
		elif not scraped_email:
			status = "no_scraped_email"
		elif email_changed:
			status = "changed"
		else:
			status = "match"

		result.append(
			{
				"dept_record": dept.name if dept else None,
				"dept_id": dept.dept_id if dept else None,
				"department": dept.dept_name if dept else r.get("department"),
				"scraped_department_title": r.get("department"),
				"scraped_name": r.get("name"),
				"scraped_email": scraped_email,
				"current_head_email": current_head_email,
				"current_head_name": current_head.full_name if current_head else None,
				"new_head_first_name": new_head_user.first_name if new_head_user else None,
				"new_head_middle_name": new_head_user.middle_name if new_head_user else None,
				"new_head_last_name": new_head_user.last_name if new_head_user else None,
				"status": status,
				"new_head_user_exists": new_user_exists,
				"new_head_is_permanent_employee": new_user_is_permanent,
				"can_update": status == "changed" and new_user_exists and new_user_is_permanent,
			}
		)
	return result


# ---------------------------------------------------------------------
# manual updates
# ---------------------------------------------------------------------

@frappe.whitelist()
def update_faculty_user(email, first_name, middle_name=None, last_name=None):
	"""Push the (admin-edited) first/middle/last name onto the matching User -- Permanent Employees only.

	The UI pre-fills these from the User's current values, so this always reflects what the
	admin sees and edits in the comparison table, not the raw scraped name.
	"""
	_require_system_manager()

	if not frappe.db.exists("User", email):
		frappe.throw(_("No User account exists for {0}.").format(email))

	if PERMANENT_EMPLOYEE_ROLE not in frappe.get_roles(email):
		frappe.throw(_("{0} does not have the {1} role -- manual update is restricted to that role.").format(
			email, PERMANENT_EMPLOYEE_ROLE
		))

	new_first = (first_name or "").strip()
	if not new_first:
		frappe.throw(_("First name cannot be empty."))
	new_middle = (middle_name or "").strip()
	new_last = (last_name or "").strip()

	user = frappe.get_doc("User", email)
	old_full_name = user.full_name
	if (new_first, new_middle, new_last) != (user.first_name or "", user.middle_name or "", user.last_name or ""):
		user.first_name = new_first
		user.middle_name = new_middle
		user.last_name = new_last
		user.save(ignore_permissions=True)
		frappe.db.commit()

	return {"ok": True, "email": email, "old_full_name": old_full_name, "new_full_name": user.full_name}


@frappe.whitelist()
def update_department_head(dept_record, head_email, head_first_name=None, head_middle_name=None, head_last_name=None):
	"""Re-point Department_prornd.dept_head at the (admin-edited) head -- Permanent Employees only.

	head_email is required and identifies which User becomes the new head. The name fields are
	optional and, when given, are pushed onto that User the same way update_faculty_user does.
	"""
	_require_system_manager()

	dept = frappe.get_doc("Department_prornd", dept_record)

	new_email = (head_email or "").strip()
	if not new_email:
		frappe.throw(_("No head-of-department email given for {0}.").format(dept.dept_name))

	if not frappe.db.exists("User", new_email):
		frappe.throw(_("No User account exists for {0}; create the account before assigning as head.").format(
			new_email
		))

	if PERMANENT_EMPLOYEE_ROLE not in frappe.get_roles(new_email):
		frappe.throw(_("{0} does not have the {1} role -- manual update is restricted to that role.").format(
			new_email, PERMANENT_EMPLOYEE_ROLE
		))

	old_head = dept.dept_head
	dept.dept_head = new_email
	dept.save(ignore_permissions=True)

	name_updated = False
	head_user = frappe.get_doc("User", new_email)
	new_first = (head_first_name or "").strip()
	if new_first:
		new_middle = (head_middle_name or "").strip()
		new_last = (head_last_name or "").strip()
		if (new_first, new_middle, new_last) != (head_user.first_name or "", head_user.middle_name or "", head_user.last_name or ""):
			head_user.first_name = new_first
			head_user.middle_name = new_middle
			head_user.last_name = new_last
			head_user.save(ignore_permissions=True)
			name_updated = True

	frappe.db.commit()
	return {"ok": True, "old_head": old_head, "new_head": new_email, "name_updated": name_updated}
