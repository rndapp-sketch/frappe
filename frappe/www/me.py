# # Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# # License: MIT. See LICENSE

# import frappe
# import frappe.www.list
# from frappe import _

# no_cache = 1


# def get_context(context):
# 	if frappe.session.user == "Guest":
# 		frappe.throw(_("You need to be logged in to access this page"), frappe.PermissionError)

# 	context.current_user = frappe.get_doc("User", frappe.session.user)
# 	context.show_sidebar = True


# Copyright (c) 2015, Frappe Technologies Pvt. Ltd.
# License: MIT. See LICENSE

import frappe
from frappe import _

no_cache = 1


def get_context(context):
	if frappe.session.user == "Guest":
		frappe.throw(_("You need to be logged in to access this page"), frappe.PermissionError)

	# Basic User doc
	user_doc = frappe.get_doc("User", frappe.session.user)

	# Additional info — must be frappe._dict so Jinja sandboxed env can do
	# attribute access (user_info.email) via getattr instead of item access.
	user_info = frappe._dict(
		full_name=user_doc.full_name,
		email=user_doc.email,
		user_type=user_doc.user_type,
		roles=[role.role for role in user_doc.roles],
		enabled=user_doc.enabled,
		last_login=user_doc.last_login,
		creation=user_doc.creation,
		mobile_no=user_doc.mobile_no,
		location=user_doc.location if hasattr(user_doc, "location") else None,
	)

	context.current_user = user_doc
	context.user_info = user_info
	context.show_sidebar = True
