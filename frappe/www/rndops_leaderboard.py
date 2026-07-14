import frappe

no_cache = 1

# All tracked doctypes and their categories
TRACKED_DOCTYPES = {
    # Purchase
    "Direct Purchase":                      "Purchase",
    "Proprietary Purchase":                 "Purchase",
    "Standerdized Purchase":                "Purchase",
    "Repair Replacement":                   "Purchase",
    "Indent General Form":                  "Purchase",
    "Indent Cum Sanction Sheet":            "Purchase",
    "Rate Contract":                        "Purchase",
    "AMC":                                  "Purchase",
    "DP PO":                                "Purchase",
    "NIQ":                                  "Purchase",
    # Financial
    "Temporary Advance":                    "Financial",
    "Advance Settlement":                   "Financial",
    "TA DA Settlement":                     "Financial",
    "Reimbursement":                        "Financial",
    "Loan Request":                         "Financial",
    "P 11 Form":                            "Financial",
    # Project
    "Project Registration":                 "Project",
    "Project Proposal":                     "Project",
    "Project Extension":                    "Project",
    "Fund Received":                        "Project",
    "Fund Sanction":                        "Project",
    "Project Sanction Details":             "Project",
    "UC Request":                           "Project",
    # HR / Staff
    "Recruitment Adhoc Contractual":        "HR / Staff",
    "Project Staff Details":                "HR / Staff",
    "Extension of Tenure of Appointment":   "HR / Staff",
    "Project Staff Resignation":            "HR / Staff",
    "Leave Module":                         "HR / Staff",
    "Top Up Fellowship":                    "HR / Staff",
    "Selection Committee Report":           "HR / Staff",
    # Deposits
    "Deposit Slip":                         "Deposits",
    "Research Deposit Slip":                "Deposits",
    "Research Consultancy Deposit Slip":    "Deposits",
    "Disbursal of Consultancy":             "Deposits",
    "Disbursal of Honorarium":              "Deposits",
    "Disbursement of Honorarium":           "Deposits",
    # Travel
    "Travel":                               "Travel",
    # IPR
    "IPR Invention Disclosure":             "IPR",
    # Other
    "Cancellation Request":                 "Other",
    "Endorsement Data":                     "Other",
    "Sanction Sheet":                       "Other",
    "PO Commit Adjustment":                 "Other",
}

_PERIOD_SQL = {
    "today":   "AND DATE(sal.timestamp) = CURDATE()",
    "week":    "AND sal.timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)",
    "month":   "AND sal.timestamp >= DATE_FORMAT(NOW(), '%%Y-%%m-01')",
    "quarter": "AND sal.timestamp >= DATE_SUB(NOW(), INTERVAL 3 MONTH)",
    "all":     "",
}

_PERIOD_COMMENT_COND = {
    "today":   "AND DATE(c.creation) = CURDATE()",
    "week":    "AND c.creation >= DATE_SUB(NOW(), INTERVAL 7 DAY)",
    "month":   "AND c.creation >= DATE_FORMAT(NOW(), '%%Y-%%m-01')",
    "quarter": "AND c.creation >= DATE_SUB(NOW(), INTERVAL 3 MONTH)",
    "all":     "",
}

# Keywords in a workflow comment's resulting state that mean the document
# was sent backwards rather than advanced/approved.
_NEGATIVE_STATE_KEYWORDS = ("reject", "put back", "correction", "cancel")

_PERIOD_LABELS = {
    "today":   "Today",
    "week":    "This Week",
    "month":   "This Month",
    "quarter": "This Quarter",
    "all":     "All Time",
}

_ROLE_LABEL_MAP = {
    "staff, RnD":                        "Staff RnD",
    "Hos, RnD (Head of Section, RnD)":   "Head of Section",
    "Associate Dean, RND":               "Associate Dean",
    "Dean, RnD":                         "Dean RnD",
    "Director":                          "Director",
    "Principal Investigator":            "Principal Investigator",
    "HoD (Head of Department)":          "Head of Department",
    "Mentor":                            "Mentor",
}

_APPROVER_ROLES = list(_ROLE_LABEL_MAP.keys())

_CATEGORIES = ["Purchase", "Financial", "Project", "HR / Staff", "Deposits", "Travel", "IPR", "Other"]

_SYSTEM_USERS = {"", "Guest", "Administrator"}


def get_context(context):
    # Defaults — template always has these even if queries fail
    context.leaderboard     = []
    context.period          = "month"
    context.period_label    = "This Month"
    context.period_labels   = _PERIOD_LABELS
    context.role_filter     = ""
    context.category_filter = ""
    context.total_processed = 0
    context.total_approved  = 0
    context.total_rejected  = 0
    context.overall_rate    = 0
    context.top_staff       = None
    context.fastest         = None
    context.pending_by_role = []
    context.has_data        = False
    context.categories      = _CATEGORIES
    context.role_label_map  = _ROLE_LABEL_MAP
    context.approver_roles  = _APPROVER_ROLES
    context.data_source     = ""

    frappe.only_for(["System Manager"] + _APPROVER_ROLES)

    args            = frappe.local.request.args
    period          = args.get("period", "month")
    role_filter     = args.get("role", "")
    category_filter = args.get("category", "")

    if period not in _PERIOD_SQL:
        period = "month"

    context.period          = period
    context.period_label    = _PERIOD_LABELS[period]
    context.role_filter     = role_filter
    context.category_filter = category_filter

    # ── Primary source: the workflow Comment trail on each docname ──
    # (`tabComment`, comment_type='Workflow'). This is the authoritative,
    # complete record of every user who acted on every document — unlike
    # the raw doctype tables (which only retain the *last* modifier) or the
    # custom "Staff Activity Log" (whose logging hook silently misses many
    # transitions, e.g. manual overrides via Admin Panel/Kafka Control).
    leaderboard = _query_workflow_comments(period, role_filter, category_filter)
    context.data_source = "comments"

    # Staff Activity Log still tracks precise queue time, so borrow avg_time
    # from it per-user where available without dropping anyone it missed.
    _merge_avg_time(leaderboard, period, category_filter)

    _enrich_rows(leaderboard)

    total_processed = sum(r.get("total_processed") or 0 for r in leaderboard)
    total_approved  = sum(r.get("approved") or 0 for r in leaderboard)
    total_rejected  = sum(r.get("rejected") or 0 for r in leaderboard)

    context.leaderboard     = leaderboard
    context.total_processed = total_processed
    context.total_approved  = total_approved
    context.total_rejected  = total_rejected
    context.overall_rate    = round(total_approved / total_processed * 100) if total_processed else 0
    context.top_staff       = leaderboard[0] if leaderboard else None
    context.fastest         = min(
        (r for r in leaderboard if r.get("avg_time")),
        key=lambda r: r["avg_time"],
        default=None,
    )
    context.has_data        = bool(leaderboard)
    context.pending_by_role = _get_pending_by_role()


def _query_workflow_comments(period, role_filter, category_filter):
    """
    Derive the leaderboard from the workflow Comment trail (tabComment,
    comment_type='Workflow'), grouped by comment_email. Frappe writes one
    of these for *every* workflow transition on *every* docname — normal
    transitions and manual overrides alike — so every acting user shows up,
    not just whoever last saved the record.
    """
    doctypes = [dt for dt, cat in TRACKED_DOCTYPES.items() if not category_filter or cat == category_filter]
    if not doctypes:
        return []

    date_cond    = _PERIOD_COMMENT_COND[period]
    placeholders = ", ".join(["%s"] * len(doctypes))

    rows = frappe.db.sql(f"""
        SELECT c.comment_email AS user, c.content AS content, c.creation AS creation
        FROM `tabComment` c
        WHERE c.comment_type = 'Workflow'
          AND c.reference_doctype IN ({placeholders})
          AND c.comment_email IS NOT NULL
          AND c.comment_email NOT IN ('', 'Guest')
          {date_cond}
    """, tuple(doctypes), as_dict=True)

    user_stats = {}
    for row in rows:
        user = row.user
        if not user or "@" not in user:
            continue

        s = user_stats.setdefault(user, {
            "user":            user,
            "total_processed": 0,
            "approved":        0,
            "rejected":        0,
            "submitted":       0,
            "avg_time":        0.0,
            "last_action":     None,
        })

        s["total_processed"] += 1
        outcome = _classify_comment_state(row.content)
        if outcome == "rejected":
            s["rejected"] += 1
        elif outcome == "approved":
            s["approved"] += 1

        if row.creation and (not s["last_action"] or row.creation > s["last_action"]):
            s["last_action"] = row.creation

    result = list(user_stats.values())
    if role_filter:
        result = [r for r in result if _user_has_role(r["user"], role_filter)]

    result.sort(key=lambda r: r["total_processed"], reverse=True)
    return result[:50]


def _classify_comment_state(content):
    """Classify a workflow Comment's resulting state as approved/rejected/neutral."""
    content = (content or "").strip()

    if content.startswith("[Manual Override]") and "→" in content:
        content = content.split("→", 1)[1].split("|", 1)[0].strip()

    low = content.lower()
    if any(k in low for k in _NEGATIVE_STATE_KEYWORDS):
        return "rejected"
    if low == "draft":
        return "neutral"
    return "approved"


def _merge_avg_time(leaderboard, period, category_filter):
    """Attach avg queue time from Staff Activity Log where available, without
    dropping users it doesn't have data for."""
    if not leaderboard:
        return

    date_cond = _PERIOD_SQL[period]
    params    = []
    cat_cond  = ""
    if category_filter:
        cat_cond = "AND sal.form_category = %s"
        params.append(category_filter)

    try:
        rows = frappe.db.sql(f"""
            SELECT sal.user, ROUND(AVG(NULLIF(sal.time_in_queue, 0)), 1) AS avg_time
            FROM `tabStaff Activity Log` sal
            WHERE 1=1 {date_cond} {cat_cond}
            GROUP BY sal.user
        """, tuple(params), as_dict=True)
    except Exception:
        return

    avg_by_user = {r.user: r.avg_time for r in rows if r.avg_time}
    for row in leaderboard:
        avg_time = avg_by_user.get(row["user"])
        if avg_time:
            row["avg_time"] = float(avg_time)


def _user_has_role(user, role):
    try:
        return role in frappe.get_roles(user)
    except Exception:
        return False


def _enrich_rows(rows):
    for i, row in enumerate(rows):
        if isinstance(row, dict):
            get = row.get
            set_ = row.__setitem__
        else:
            get = lambda k, d=None: getattr(row, k, d)
            set_ = lambda k, v: setattr(row, k, v)

        set_("rank", i + 1)

        user = get("user") or ""
        user_info = frappe.db.get_value(
            "User", user, ["full_name", "user_image"], as_dict=True
        ) or {}
        set_("full_name",  user_info.get("full_name") or user.split("@")[0])
        set_("user_image", user_info.get("user_image") or "")
        set_("email",      user)
        set_("approved",   int(get("approved") or 0))
        set_("rejected",   int(get("rejected") or 0))
        set_("submitted",  int(get("submitted") or 0))
        set_("avg_time",   float(get("avg_time") or 0))

        user_roles = frappe.get_roles(user)
        set_("primary_role", next(
            (_ROLE_LABEL_MAP[r] for r in _APPROVER_ROLES if r in user_roles),
            "Staff",
        ))

        total = int(get("total_processed") or 0)
        approved = int(get("approved") or 0)
        set_("total_processed", total)
        set_("approval_rate", round(approved / total * 100) if total else 0)

        avg_time = float(get("avg_time") or 0)
        set_("avg_time_color",
            "green"  if avg_time and avg_time < 24
            else "orange" if avg_time and avg_time < 48
            else "red"    if avg_time
            else "zero"
        )


def _get_pending_by_role():
    """
    Live pending queue: query each tracked doctype for forms currently
    in a Pending workflow state, then group by state.
    """
    state_to_role = {
        "Pending Staff Approval":    "Staff RnD",
        "Pending HoS Approval":      "Head of Section",
        "Pending Associate Dean":    "Associate Dean",
        "Pending Dean Approval":     "Dean RnD",
        "Pending Director Approval": "Director",
        "Pending PI Approval":       "Principal Investigator",
        "Pending HoD Approval":      "Head of Department",
        "Pending Mentor Approval":   "Mentor",
        "Pending Other PI":          "Other PI",
    }

    pending_counts = {}

    for doctype in TRACKED_DOCTYPES:
        table = f"`tab{doctype}`"
        try:
            rows = frappe.db.sql(f"""
                SELECT workflow_state AS state, COUNT(*) AS cnt
                FROM {table}
                WHERE workflow_state LIKE 'Pending%%'
                GROUP BY workflow_state
            """, as_dict=True)
        except Exception:
            continue

        for row in rows:
            state = row.state or ""
            pending_counts[state] = pending_counts.get(state, 0) + row.cnt

    result = []
    for state, cnt in sorted(pending_counts.items(), key=lambda x: -x[1]):
        result.append({
            "role":  state_to_role.get(state, state),
            "state": state,
            "count": cnt,
        })
    return result
