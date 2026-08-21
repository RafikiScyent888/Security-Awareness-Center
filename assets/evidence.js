/* =====================================================================
   Security Awareness Center — evidence renderers

   Turns the ground-truth breach into the artefacts each domain lens would
   actually have in front of it: the message or badge log the human layer
   sees, the indicator table, the control inventory, the access matrix.
   Malicious rows carry a `_t` tag so instructor mode can highlight them
   and the grader can count without a second source of truth.
   ===================================================================== */
import { mulberry32, hhmm, hhmmss, IR_PHASES } from "./breach.js";

function R(seed) {
  var rng = mulberry32(seed);
  return { int: (a, b) => a + Math.floor(rng() * (b - a + 1)), pick: (a) => a[Math.floor(rng() * a.length)] };
}

const BENIGN_SUBJECTS = [
  "Q3 all-hands deck", "Timesheet reminder", "Parking permit renewal", "Wellness week schedule",
  "Vendor invoice #4471", "Team offsite — please RSVP", "IT maintenance window Saturday",
  "Updated expenses policy", "New starter introduction", "Payroll calendar 2026"
];
const BENIGN_SENDERS = ["hr", "facilities", "finance", "it-notices", "comms", "payroll"];

/* ---------------- the human layer ---------------- */
/* For a message-borne vector this is a mail log; for a physical one it is
   the badge/visitor record. Either way the student is looking for the one
   artefact that does not hold up, among a dozen that do. */
export function humanEvidence(G) {
  var r = R(G.slot * 37 + 7);
  var rows = [];
  var t0 = G.t0;
  var v = G.human;

  if (!v) {
    // Technical entry — the human layer still has something to judge:
    // who noticed, who did not, and what the helpdesk did with it.
    rows.push({ t: t0 + r.int(1800, 2600), who: G.reporter.name, dept: G.reporter.dept,
      what: "Called the service desk: 'something looks wrong with the file share'",
      outcome: "Ticket raised", _t: "good" });
    rows.push({ t: t0 + r.int(600, 1500), who: G.ignorer.name, dept: G.ignorer.dept,
      what: "Saw a certificate warning and clicked through it", outcome: "No report", _t: "bad" });
    rows.push({ t: t0 + r.int(200, 900), who: G.victim.name, dept: G.victim.dept,
      what: "Approved an unexpected MFA prompt to make it stop", outcome: "No report", _t: "bad" });
    for (var i = 0; i < 6; i++) {
      var s = G.staff[r.int(3, G.staff.length - 1)];
      rows.push({ t: t0 + r.int(-1800, 3600), who: s.name, dept: s.dept,
        what: r.pick(["Reported a suspected phishing email (was legitimate)",
          "Asked the service desk to reset a forgotten password",
          "Requested access to a shared mailbox",
          "Reported a lost badge"]),
        outcome: r.pick(["Closed — no issue", "Resolved", "Access granted after approval"]), _t: "benign" });
    }
    rows.sort((a, b) => a.t - b.t);
    return { kind: "reports", rows: rows };
  }

  if (v.channel === "Physical") {
    // badge / visitor evidence
    rows.push({ t: t0, badge: "—", who: "Unidentified (delivery uniform)", door: "Lobby turnstile",
      result: "No swipe — followed " + G.victim.name + " through", _t: "attack" });
    rows.push({ t: t0 - r.int(30, 180), badge: G.victim.user.toUpperCase(), who: G.victim.name,
      door: "Lobby turnstile", result: "Granted", _t: "benign" });
    if (v.key === "usb") {
      rows.push({ t: t0 + r.int(300, 900), badge: "—", who: G.victim.name, door: G.victim.host,
        result: "Removable device connected — serial not in asset register", _t: "attack" });
    }
    rows.push({ t: t0 + r.int(120, 400), badge: G.ignorer.user.toUpperCase(), who: G.ignorer.name,
      door: "Lobby turnstile", result: "Granted — saw the follower, said nothing", _t: "bad" });
    rows.push({ t: t0 + r.int(2400, 3200), badge: G.reporter.user.toUpperCase(), who: G.reporter.name,
      door: "Service desk", result: "Reported an unbadged person on floor 2", _t: "good" });
    for (var j = 0; j < 8; j++) {
      var s2 = G.staff[r.int(3, G.staff.length - 1)];
      rows.push({ t: t0 + r.int(-3600, 3600), badge: s2.user.toUpperCase(), who: s2.name,
        door: r.pick(["Lobby turnstile", "Server room", "Rear entrance", "Car park barrier"]),
        result: r.pick(["Granted", "Granted", "Denied — expired badge"]), _t: "benign" });
    }
    rows.sort((a, b) => a.t - b.t);
    return { kind: "badge", rows: rows };
  }

  /* Message-borne. The log has to match the channel the vector actually used:
     an SMS log full of email addresses contradicts the tell that says the
     sender was a plain mobile number, and a student who ticks that tell would
     be right about the world and wrong about the page. */
  var lookalike = G.org.short.replace(/([aeiou])/, "$1$1");   // one-character-off domain
  var handset = function (p) { return "+1 (555) 0" + (100 + p); };
  var chan = v.channel;                                        // Email | SMS | Phone
  var addr, blockedNote, benignFrom, benignSubject, cols;

  if (chan === "Email") {
    addr = function (p) { return p.email; };
    cols = { from: "From", to: "To", subject: "Subject / pretext" };
    blockedNote = "Quarantined by the mail gateway";
    benignFrom = function () { return r.pick(BENIGN_SENDERS) + "@" + G.org.short + ".com"; };
    benignSubject = function () { return r.pick(BENIGN_SUBJECTS); };
  } else if (chan === "SMS") {
    addr = function (p, i) { return handset(20 + i) + " (personal handset)"; };
    cols = { from: "From", to: "To", subject: "Message" };
    blockedNote = "Blocked by the carrier spam filter";
    benignFrom = function () { return r.pick(["72445", "88202", "31610"]) + " (short code)"; };
    benignSubject = function () {
      return r.pick(["Your verification code is 4-digit and expires in 10 minutes",
        "Appointment reminder for tomorrow", "Your parcel is out for delivery",
        "Balance alert: statement ready"]);
    };
  } else {                                                     // Phone
    addr = function (p) { return p.name + " — ext. " + (2000 + (p.user.length * 37) % 900); };
    cols = { from: "Calling number", to: "Extension", subject: "Reported content of the call" };
    blockedNote = "Rejected — number already on the block list";
    benignFrom = function () { return handset(r.int(200, 700)); };
    benignSubject = function () {
      return r.pick(["Supplier confirming a delivery slot", "Candidate returning a recruiter's call",
        "Customer chasing an invoice", "Courier asking for gate access"]);
    };
  }

  var attackFrom = chan === "Email" ? "it-support@" + lookalike + ".com"
    : chan === "SMS" ? handset(13) + " (unregistered mobile)"
      : handset(13) + " — spoofed to the internal helpdesk extension";

  rows.push({ t: t0, from: attackFrom, to: addr(G.victim, 1), subject: v.pretext,
    action: chan === "Phone" ? "Answered — complied" : "Delivered — acted on", _t: "attack" });
  rows.push({ t: t0 + r.int(60, 400), from: attackFrom, to: addr(G.ignorer, 2), subject: v.pretext,
    action: chan === "Phone" ? "Answered — no report" : "Delivered — no report", _t: "bad" });
  rows.push({ t: t0 + r.int(80, 500), from: attackFrom, to: addr(G.reporter, 3), subject: v.pretext,
    action: "Reported to service desk", _t: "good" });
  // one that did get stopped — the control caught some of it, not all of it
  rows.push({ t: t0 + r.int(30, 200), from: attackFrom, to: addr(G.staff[3], 4), subject: v.pretext,
    action: blockedNote, _t: "blocked" });

  for (var k = 0; k < 9; k++) {
    var s3 = G.staff[r.int(0, G.staff.length - 1)];
    rows.push({ t: t0 + r.int(-3600, 3600), from: benignFrom(), to: addr(s3, 5 + k),
      subject: benignSubject(), action: chan === "Phone" ? "Answered" : "Delivered", _t: "benign" });
  }
  rows.sort((a, b) => a.t - b.t);
  return { kind: "mail", channel: chan, cols: cols, rows: rows, lookalike: lookalike };
}

/* ---------------- indicators of malicious activity (2.4) ---------------- */
export function indicatorRows(G) {
  var r = R(G.slot * 41 + 3);
  var rows = [
    { ind: "Account lockouts across several users in a short window", real: true,
      why: "Consistent with credential spraying against many accounts at once." },
    { ind: "Impossible travel — two logons from distant regions minutes apart", real: true,
      why: "One identity cannot be in both places; a session was replayed or stolen." },
    { ind: "Out-of-cycle logging: a host stopped sending logs entirely", real: true,
      why: "Missing telemetry is itself a finding. Silence is not health." },
    { ind: "Resource consumption climbed on a file server overnight", real: true,
      why: "Consistent with bulk staging or encryption of data." },
    { ind: "Scheduled backup job completed at its usual time", real: false,
      why: "Routine and expected. Present to be dismissed." },
    { ind: "Monthly patch cycle rebooted several servers on Sunday", real: false,
      why: "Change-managed and announced. Explained by the change record." },
    { ind: "A user changed their own password after a helpdesk reset", real: false,
      why: "Exactly what is supposed to happen after a reset." },
    { ind: "Blocked connection attempts on the perimeter from the open internet", real: false,
      why: "Constant background scanning. The firewall denied them, which is the firewall working." }
  ];
  // a couple that only make sense for this scenario
  if (G.human && G.human.key === "usb") {
    rows.push({ ind: "Removable device with a serial absent from the asset register", real: true,
      why: "Asset management exists so an unknown device is visible as unknown." });
  }
  if (G.iam.mfa.indexOf("service accounts") !== -1) {
    rows.push({ ind: "A service account authenticating interactively at 02:00", real: true,
      why: "Service accounts should not log on interactively, and not at that hour." });
  }
  // Interleave properly. Listed as written the four real ones sit together at
  // the top, and "tick the first half" scores full marks without reading.
  for (var i = rows.length - 1; i > 0; i--) {
    var j = r.int(0, i), tmp = rows[i]; rows[i] = rows[j]; rows[j] = tmp;
  }
  return rows;
}

/* ---------------- control inventory (1.1, 2.5) ---------------- */
export function controlRows(G) {
  var r = R(G.slot * 59 + 11);
  var rows = [
    { name: G.controls.presentButWrong.name, type: G.controls.presentButWrong.type,
      cat: G.controls.presentButWrong.cat, status: "In place", _t: "wrong-kind" },
    { name: G.controls.wouldHave, type: G.controls.correctType, cat: G.controls.correctCat,
      status: "NOT in place", _t: "missing" },
    { name: "Endpoint protection with behavioural detection", type: "Detective", cat: "Technical", status: "In place", _t: "benign" },
    { name: "Nightly encrypted backup", type: "Corrective", cat: "Technical", status: "In place", _t: "benign" },
    { name: "Acceptable use policy, signed at onboarding", type: "Directive", cat: "Managerial", status: "In place", _t: "benign" },
    { name: "Visitor sign-in book at reception", type: "Detective", cat: "Physical", status: "In place", _t: "benign" },
    { name: "Separation of duties on payment approval", type: "Preventive", cat: "Managerial", status: "In place", _t: "benign" }
  ];
  // The two rows that matter are written first. Shuffle so the inventory has
  // to be read rather than skimmed off the top.
  for (var i = rows.length - 1; i > 0; i--) {
    var j = r.int(0, i), tmp = rows[i]; rows[i] = rows[j]; rows[j] = tmp;
  }
  return rows;
}

/* ---------------- response log (4.8, 4.9) ---------------- */
export function responseRows(G) {
  var r = R(G.slot * 53 + 9);
  var t = G.t0 + 3000;
  var good = [
    { action: "Service desk ticket raised from " + G.reporter.name + "'s report", phase: "Detection & Analysis", ok: true },
    { action: "Analyst confirmed the alert was a true positive", phase: "Detection & Analysis", ok: true },
    { action: "Affected host removed from the network", phase: "Containment", ok: true },
    { action: "Malicious persistence removed and credentials rotated", phase: "Eradication", ok: true },
    { action: "Service restored and monitored for recurrence", phase: "Recovery", ok: true }
  ];
  // Slot the mistake in where its own IR phase puts it, rather than always at
  // position three — the phase varies per scenario, so the position does too,
  // and the log still reads in a sensible order.
  var order = IR_PHASES;
  var at = good.length;
  for (var i = 0; i < good.length; i++) {
    if (order.indexOf(good[i].phase) > order.indexOf(G.respMiss.phase)) { at = i; break; }
  }
  var rows = good.slice(0, at)
    .concat([{ action: G.respMiss.miss, phase: G.respMiss.phase, ok: false, _t: "miss" }])
    .concat(good.slice(at));
  var clock = t;
  rows.forEach(function (row) { clock += r.int(180, 520); row.t = clock; });
  return rows;
}

export { hhmm, hhmmss };
