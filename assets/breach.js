/* =====================================================================
   Security Awareness Center — breach generator

   One object is the single source of truth for a scenario. Every tile is a
   different SY0-701 lens onto it, and every graded answer is COMPUTED from
   this object rather than written beside the rows — the same contract as
   the CySA build, for the same reason: hand-matched answers drift the
   moment anything regenerates.

   Security+ is not a SOC-analyst exam, so the lenses are domains rather
   than tools: the human layer, the threat, the control that failed, the
   architecture gap, identity and crypto, the response, and the risk.
   ===================================================================== */

export function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    var t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function R(rng) {
  return {
    int: (lo, hi) => lo + Math.floor(rng() * (hi - lo + 1)),
    pick: (a) => a[Math.floor(rng() * a.length)],
    shuffle: (a) => { var x = a.slice(); for (var i = x.length - 1; i > 0; i--) { var j = Math.floor(rng() * (i + 1)); var t = x[i]; x[i] = x[j]; x[j] = t; } return x; },
    some: (a, n) => { var x = a.slice(), o = []; for (var i = 0; i < n && x.length; i++) o.push(x.splice(Math.floor(rng() * x.length), 1)[0]); return o; },
    chance: (p) => rng() < p
  };
}

/* ---------------- reference data ---------------- */
export const CONTROL_TYPES = {
  Preventive: "Stops the act before it happens",
  Detective: "Notices that it happened",
  Corrective: "Puts things right afterwards",
  Deterrent: "Discourages the attempt",
  Compensating: "Stands in when the primary control is not feasible",
  Directive: "Tells people what they are required to do"
};
export const CONTROL_CATS = {
  Technical: "Enforced by a system",
  Managerial: "A policy or process decision",
  Operational: "Carried out by people, day to day",
  Physical: "Acts on the physical world"
};
/* Notification deadlines students have to keep apart. GDPR's 72 hours is the
   one that gets applied to everything, so it is always on the list and never
   the answer — none of these organisations sit under GDPR. */
const CLOCKS_EXTRA = ["72 hours", "24 hours", "7 days"];
export function ALL_CLOCKS() {
  var seen = {}, out = [];
  ORGS.map(function (o) { return o.clock; }).concat(CLOCKS_EXTRA).forEach(function (c) {
    if (!seen[c]) { seen[c] = 1; out.push(c); }
  });
  return out;
}

export const IR_PHASES = ["Preparation", "Detection & Analysis", "Containment",
  "Eradication", "Recovery", "Lessons Learned"];
export const VOLATILITY = ["CPU registers & cache", "RAM / running processes",
  "Network state & connections", "Disk", "Remote logging & archived media", "Physical backups"];

const ORGS = [
  { name: "Meridian Health", short: "meridian", data: "PHI (patient records)", reg: "HIPAA", clock: "60 days", regNote: "HIPAA breach notification to HHS and individuals within 60 days" },
  { name: "Cadence Bank", short: "cadence", data: "cardholder data", reg: "PCI DSS", clock: "Immediately", regNote: "PCI DSS — card brands and the acquirer are notified immediately on suspicion" },
  { name: "Northwind Logistics", short: "northwind", data: "customer shipping records", reg: "state breach law", clock: "30 days", regNote: "state breach notification statute, 30 days from determination" },
  { name: "Arclight Energy", short: "arclight", data: "SCADA/OT telemetry", reg: "NERC CIP", clock: "1 hour", regNote: "NERC CIP-008 — E-ISAC reporting within 1 hour of determination" },
  { name: "Vantage Legal", short: "vantage", data: "privileged client files", reg: "bar professional rules", clock: "No fixed statutory clock \u2014 promptly, under professional conduct rules", regNote: "no statute sets the deadline; the duty to inform clients promptly does" },
  { name: "Halden University", short: "halden", data: "student records", reg: "FERPA", clock: "No fixed statutory clock \u2014 FERPA sets recordkeeping, not a notification deadline", regNote: "FERPA requires a record of the disclosure; it sets no notification clock" }
];

const FIRST = ["Dana", "Marcus", "Priya", "Aiden", "Rosa", "Tomas", "Nadia", "Chen", "Kofi",
  "Lena", "Ravi", "Maya", "Erik", "Sofia", "Jamal", "Iris", "Otto", "Talia"];
const LAST = ["Whitfield", "Obi", "Nakamura", "Reyes", "Kaur", "Lindqvist", "Amari", "Bauer",
  "Castellanos", "Duarte", "Fontaine", "Greer", "Halloran", "Ivanov"];
const DEPTS = ["Finance", "HR", "Legal", "Sales", "Engineering", "Operations", "Facilities", "Support"];

export const ACTORS = [
  { type: "Organized crime", motive: "Financial gain", sophistication: "High", funding: "Well resourced",
    tell: "moves straight to anything monetisable and negotiates" },
  { type: "Nation-state", motive: "Espionage", sophistication: "High", funding: "State funded",
    tell: "stays quiet for a long time and takes only what it came for" },
  { type: "Insider threat", motive: "Revenge / financial", sophistication: "Low to medium", funding: "None",
    tell: "already had the access, so nothing had to be broken to get in" },
  { type: "Hacktivist", motive: "Philosophical / political", sophistication: "Medium", funding: "Little",
    tell: "wants it seen — defacement or a public dump rather than quiet theft" },
  { type: "Unskilled attacker", motive: "Notoriety / opportunism", sophistication: "Low", funding: "None",
    tell: "used an off-the-shelf kit and made a great deal of noise doing it" },
  { type: "Shadow IT", motive: "Convenience, not malice", sophistication: "Low", funding: "N/A",
    tell: "no attacker at all — staff routed around a control that got in their way" }
];

/* Human-layer entry vectors. Awareness is a first-class lens here, so most
   scenarios carry one; the technical vectors below still leave a human
   decision somewhere for that tile to bite on. */
export const PRINCIPLES = {
  Authority: "Authority — the request appears to come from someone entitled to make it",
  Urgency: "Urgency — a deadline that removes the time to check",
  Familiarity: "Familiarity — it trades on a brand or relationship the target already trusts",
  Curiosity: "Curiosity — the target opens it because they want to know what it is",
  Consensus: "Consensus — everyone else has already complied",
  Scarcity: "Scarcity — a limited supply of something desirable",
  Intimidation: "Intimidation — complying feels safer than being difficult"
};

const HUMAN_VECTORS = [
  { key: "phish", label: "Phishing email", channel: "Email", principle: "Urgency",
    pretext: "a shared document that needs re-authentication",
    tells: ["display name matches a real colleague but the reply-to is external",
            "the link text and the actual href do not agree",
            "urgency: 'access will be revoked in 2 hours'"],
    control: "Email security gateway with link rewriting" },
  { key: "vishing", label: "Vishing call", channel: "Phone", principle: "Authority",
    pretext: "IT support calling about a failed patch, needing the MFA code read back",
    tells: ["caller asked the user to read out a code, which no real helpdesk does",
            "inbound number spoofed to the internal helpdesk extension",
            "pressure to stay on the line and not call back"],
    control: "Callback verification procedure for any credential request" },
  { key: "smish", label: "Smishing / SMS", channel: "SMS", principle: "Familiarity",
    pretext: "a delivery-fee message with a payment link",
    tells: ["shortened link hiding the real destination",
            "message arrived out of hours to a personal handset",
            "sender is a plain mobile number, not a registered short code"],
    control: "Awareness training on out-of-band verification" },
  { key: "bec", label: "Business email compromise", channel: "Email", principle: "Authority",
    pretext: "the CFO asking for an urgent supplier bank-detail change",
    tells: ["request bypasses the normal change process",
            "sender domain differs by one character from the real one",
            "asks the recipient to keep it confidential"],
    control: "Dual authorisation on payment detail changes" },
  { key: "tailgate", label: "Tailgating", channel: "Physical", principle: "Familiarity",
    pretext: "someone in a delivery uniform with full hands at the badge door",
    tells: ["no badge swipe recorded for that person at that door",
            "one badge, two people through the door on the same event",
            "visitor log has no matching entry"],
    control: "Access control vestibule (mantrap)" },
  { key: "usb", label: "Removable media drop", channel: "Physical", principle: "Curiosity",
    pretext: "a branded USB stick left in the car park",
    tells: ["removable device connected minutes after arrival in the car park",
            "device serial not in the asset register",
            "autorun payload executed under a standard user"],
    control: "Endpoint device control blocking unapproved removable media" }
];

const TECH_VECTORS = [
  { key: "unpatched", label: "Unpatched internet-facing service",
    detail: "a known CVE on an edge appliance left past its remediation window",
    control: "Vulnerability management with an enforced patch SLA" },
  { key: "thirdparty", label: "Third-party / supply chain",
    detail: "a managed service provider's account used to reach the estate",
    control: "Third-party access review and contractual security requirements" },
  { key: "misconfig", label: "Cloud misconfiguration",
    detail: "a storage bucket left readable to any authenticated principal",
    control: "Configuration baseline with automated drift detection" },
  { key: "credstuff", label: "Credential stuffing",
    detail: "reused passwords replayed from a public breach corpus",
    control: "MFA on all externally reachable authentication" }
];

const ARCH_GAPS = [
  { gap: "Flat network — no segmentation between user VLANs and the server estate",
    fix: "Segmentation", why: "One compromised workstation could reach the data tier directly.",
    domain: "3.2 Enterprise Infrastructure Security" },
  { gap: "Implicit trust inside the perimeter — anything on the LAN was treated as authorised",
    fix: "Zero Trust", why: "Trust was granted by location rather than verified per request.",
    domain: "3.1 Architecture Models" },
  { gap: "Production data held in cleartext at rest on the file share",
    fix: "Encryption at rest", why: "The copy taken was immediately readable.",
    domain: "3.3 Data Protection" },
  { gap: "Backups on the same domain, reachable with the same credentials",
    fix: "Offline / immutable backups", why: "The recovery path shared the failure domain with production.",
    domain: "3.4 Resilience & Recovery" },
  { gap: "No egress filtering — outbound traffic to anywhere on any port",
    fix: "Egress filtering", why: "Nothing stood between the foothold and the outside.",
    domain: "3.2 Enterprise Infrastructure Security" },
  { gap: "Single site, no tested failover for the affected service",
    fix: "Tested recovery site", why: "Recovery time was set by improvisation rather than design.",
    domain: "3.4 Resilience & Recovery" }
];

const CRYPTO_ISSUES = [
  { issue: "Passwords stored as unsalted MD5 hashes", fix: "Salted, memory-hard hashing (bcrypt/Argon2)",
    why: "Unsalted fast hashes fall to rainbow tables; the salt is what defeats precomputation." },
  { issue: "TLS 1.0 still enabled on the external portal", fix: "TLS 1.2 minimum, 1.3 preferred",
    why: "Deprecated versions keep cipher suites with known practical attacks." },
  { issue: "Self-signed certificate on an internal service users were told to click past",
    fix: "Internal CA-issued certificates", why: "Training users to bypass warnings destroys the warning." },
  { issue: "Symmetric key shared by every application that needed it", fix: "Per-service keys with rotation",
    why: "One disclosure compromises everything holding the same key." },
  { issue: "Private key stored beside the certificate on the web root", fix: "Key stored in an HSM or key vault",
    why: "A readable private key makes the certificate meaningless." }
];

const RESP_MISSES = [
  { miss: "The host was reimaged before memory was captured", phase: "Detection & Analysis",
    why: "Reimaging destroys the most volatile evidence first — RAM outranks disk in the order of volatility." },
  { miss: "Containment waited on a change advisory board meeting", phase: "Containment",
    why: "Emergency change procedures exist precisely so containment is not queued behind routine governance." },
  { miss: "The compromised account was disabled but its active sessions were never revoked", phase: "Eradication",
    why: "Disabling an account does not terminate tokens already issued." },
  { miss: "Systems were restored from a backup taken after the initial compromise", phase: "Recovery",
    why: "Restoring past the intrusion date reintroduces the foothold." },
  { miss: "No lessons-learned review was scheduled once service was back", phase: "Lessons Learned",
    why: "The control gap that allowed it stays open until something forces the change." }
];

/* Role/permission material for the configure tile. The breach spreads through
   exactly one over-granted role, and the student has to find it without
   stripping the access the business actually needs. */
const RESOURCES = [
  { key: "hr", label: "HR records share" },
  { key: "fin", label: "Finance / payments system" },
  { key: "src", label: "Source code repository" },
  { key: "cust", label: "Customer database" },
  { key: "bak", label: "Backup console" },
  { key: "dom", label: "Domain admin console" }
];
const ROLES = [
  { key: "helpdesk", label: "Helpdesk technician", needs: ["hr"] },
  { key: "accounts", label: "Accounts payable clerk", needs: ["fin"] },
  { key: "dev", label: "Application developer", needs: ["src"] },
  { key: "analyst", label: "Support analyst", needs: ["cust"] },
  { key: "contractor", label: "Third-party contractor", needs: ["src"] }
];

/* ---------------- the network, for the remediation tile ----------------
   Small on purpose. The point is not to model an enterprise, it is to make
   first-match-wins and the implicit deny at the bottom something a student
   has to actually get right. Every resource sits in exactly one zone on
   exactly one service, so no two flows are indistinguishable and there is
   always a rule set that stops the breach without breaking the business. */
export const ZONES = {
  internet: "The internet",
  dmz: "DMZ / public portal",
  user: "User VLAN",
  srv: "Server estate",
  bak: "Backup network",
  mgmt: "Management network"
};
export const SERVICES = {
  web: "HTTPS (443)",
  app: "App HTTPS (8443)",
  smb: "SMB (445)",
  ssh: "SSH (22)",
  sql: "SQL (1433)",
  bakadmin: "Backup console (8080)",
  rdp: "RDP (3389)",
  c2: "Arbitrary high port (49152+)"
};
const RES_NET = {
  hr: { zone: "srv", svc: "smb" },
  fin: { zone: "srv", svc: "app" },
  src: { zone: "srv", svc: "ssh" },
  cust: { zone: "srv", svc: "sql" },
  bak: { zone: "bak", svc: "bakadmin" },
  dom: { zone: "mgmt", svc: "rdp" }
};

/* First match wins; anything that falls off the end is denied. */
export function ruleMatches(rule, flow) {
  return (rule.src === "any" || rule.src === flow.src)
    && (rule.dst === "any" || rule.dst === flow.dst)
    && (rule.svc === "any" || rule.svc === flow.svc);
}
export function evaluateFlow(rules, flow) {
  for (var i = 0; i < rules.length; i++) {
    if (ruleMatches(rules[i], flow)) return { allowed: rules[i].action === "allow", rule: i + 1 };
  }
  return { allowed: false, rule: 0 };   // implicit deny
}

/* ---------------- helpers ---------------- */
function pad(n) { return n < 10 ? "0" + n : "" + n; }
export function hhmm(sec) { return pad(Math.floor(sec / 3600) % 24) + ":" + pad(Math.floor(sec / 60) % 60); }
export function hhmmss(sec) { return hhmm(sec) + ":" + pad(sec % 60); }

/* Deal fifteen distinct openings so no two scenarios in a session share an
   entry vector + actor pairing. */
export function dealSession(seed) {
  var r = R(mulberry32(seed * 2654435761));
  var pool = [];
  HUMAN_VECTORS.forEach(function (v) { ACTORS.forEach(function (a) { pool.push({ human: v, actor: a }); }); });
  TECH_VECTORS.forEach(function (v) { ACTORS.forEach(function (a) { pool.push({ tech: v, actor: a }); }); });
  // Bias toward human entry: awareness is a first-class lens on this page.
  var human = r.shuffle(pool.filter(function (p) { return p.human; })).slice(0, 9);
  var tech = r.shuffle(pool.filter(function (p) { return p.tech; })).slice(0, 6);
  return r.shuffle(human.concat(tech));
}

export function buildBreach(seed, slot) {
  var rng = mulberry32(seed * 7919 + slot * 104729);
  var r = R(rng);
  var hand = dealSession(seed)[(slot - 1) % 15];
  var org = r.pick(ORGS);
  // Smishing's own tell says the message arrived out of hours to a personal
  // handset, so the log has to be timestamped out of hours or the evidence
  // argues with the answer.
  var t0 = (hand.human && hand.human.key === "smish")
    ? r.int(19, 22) * 3600 + r.int(0, 59) * 60
    : r.int(8, 15) * 3600 + r.int(0, 59) * 60;

  var staff = r.some(FIRST, 10).map(function (f) {
    var l = r.pick(LAST), user = (f[0] + l).toLowerCase();
    return { user: user, name: f + " " + l, dept: r.pick(DEPTS),
      email: user + "@" + org.short + ".com",
      host: "WS-" + r.pick(["FIN", "HR", "LEG", "SLS", "ENG", "OPS"]) + "-" + r.int(100, 999) };
  });

  var victim = staff[0];
  var reporter = staff[1];              // someone did the right thing
  var ignorer = staff[2];               // someone saw it and did nothing

  var G = {
    slot: slot, org: org, staff: staff, t0: t0,
    victim: victim, reporter: reporter, ignorer: ignorer,
    actor: hand.actor,
    human: hand.human || null,
    tech: hand.tech || null,
    entryLabel: hand.human ? hand.human.label : hand.tech.label
  };

  /* ---- controls: the one that failed, and the one that would have held ---- */
  var wouldHave = hand.human ? hand.human.control : hand.tech.control;
  G.controls = {
    wouldHave: wouldHave,
    // the control that existed but was the wrong kind for this job
    presentButWrong: r.pick([
      { name: "Annual awareness training slide deck", type: "Directive", cat: "Managerial",
        why: "Directive controls tell people what to do; they do not stop the act." },
      { name: "CCTV covering the lobby", type: "Detective", cat: "Physical",
        why: "It records what happened. Nothing about it prevents entry." },
      { name: "Warning banner on the logon screen", type: "Deterrent", cat: "Managerial",
        why: "Deterrents discourage. They do not enforce." },
      { name: "Quarterly access review spreadsheet", type: "Detective", cat: "Managerial",
        why: "A review that runs quarterly cannot catch a grant made on a Tuesday." }
    ]),
    // The control that would have held is preventive by definition — that is
    // what "would have prevented this" means. The interesting type question is
    // the one that was in place and did not help, so the tile asks about that.
    correctType: "Preventive",
    correctCat: hand.human
      ? (hand.human.key === "tailgate" || hand.human.key === "usb" ? "Physical" : "Technical")
      : "Technical"
  };

  G.arch = r.pick(ARCH_GAPS);
  G.crypto = r.pick(CRYPTO_ISSUES);
  G.respMiss = r.pick(RESP_MISSES);

  /* ---- identity: exactly one role is over-granted ---- */
  var roles = r.shuffle(ROLES).slice(0, 4).map(function (x) { return Object.assign({}, x); });
  var over = roles[r.int(0, roles.length - 1)];
  var extra = r.pick(RESOURCES.filter(function (res) { return over.needs.indexOf(res.key) === -1; }));
  over.granted = over.needs.concat([extra.key]);
  roles.forEach(function (x) { if (!x.granted) x.granted = x.needs.slice(); });
  var mfaExempt = r.chance(0.5);
  G.iam = {
    roles: roles,
    resources: RESOURCES,
    overGranted: over,
    extraKey: extra.key,
    extraLabel: extra.label,
    // the account the attacker landed on belongs to the over-granted role
    compromisedRole: over.key,
    mfa: mfaExempt
      ? "MFA enforced for staff, exempted for service accounts"
      : "MFA enforced only on the VPN",
    mfaGap: mfaExempt ? "service accounts" : "everything except the VPN"
  };

  /* ---- risk & compliance ---- */
  var likelihood = r.pick(["Low", "Medium", "High"]);
  var impact = r.pick(["Medium", "High", "Critical"]);
  G.risk = {
    likelihood: likelihood, impact: impact,
    records: r.int(400, 90000),
    // the decision a business actually has to make
    options: r.shuffle(["Accept", "Avoid", "Transfer", "Mitigate"]),
    correct: (impact === "Critical" || impact === "High") ? "Mitigate" : "Accept",
    thirdParty: hand.tech && hand.tech.key === "thirdparty",
    clock: org.clock, regNote: org.regNote,
    appetite: r.pick(["low", "moderate"])
  };

  /* ---- the firewall the student has to repair ----
     The starting rule set is the one that let this happen: a blanket allow off
     the user VLAN, added for a real reason years ago and never revisited. The
     fix is not "deny everything from users" — two of the flows below are that
     VLAN doing legitimate work, and denying them fails. */
  var extraNet = RES_NET[extra.key];
  var needKey = over.needs[0];
  var needNet = RES_NET[needKey];
  var needLabel = RESOURCES.filter(function (x) { return x.key === needKey; })[0].label;
  G.net = {
    flows: [
      { src: "user", dst: extraNet.zone, svc: extraNet.svc, allow: false,
        label: "The compromised " + over.label.toLowerCase() + " account reaching " + extra.label },
      { src: "user", dst: "internet", svc: "c2", allow: false,
        label: "A workstation calling out to the attacker's infrastructure" },
      { src: "user", dst: "internet", svc: "web", allow: true,
        label: "Staff browsing the web" },
      { src: "user", dst: "dmz", svc: "web", allow: true,
        label: "Staff using the organisation's own public portal" },
      { src: "user", dst: needNet.zone, svc: needNet.svc, allow: true,
        label: over.label + " doing the job — " + needLabel },
      { src: "dmz", dst: "srv", svc: "sql", allow: true,
        label: "The portal reading its own database" },
      { src: "mgmt", dst: "srv", svc: "rdp", allow: true,
        label: "Administrators managing the servers" },
      { src: "srv", dst: "bak", svc: "bakadmin", allow: true,
        label: "The nightly backup job" }
    ],
    startRules: [
      { action: "allow", src: "user", dst: "any", svc: "any",
        note: "Legacy — added during the office move, never revisited" },
      { action: "allow", src: "dmz", dst: "srv", svc: "sql" },
      { action: "allow", src: "mgmt", dst: "srv", svc: "rdp" },
      { action: "allow", src: "srv", dst: "bak", svc: "bakadmin" }
    ]
  };

  /* ---- what to implement, beyond the firewall ----
     Correct set is the four things that address THIS breach. The decoys are
     real controls drawn from the scenarios this one is not — plausible,
     fundable, and irrelevant here, which is the judgement being tested. */
  var otherArch = ARCH_GAPS.filter(function (a) { return a.fix !== G.arch.fix; });
  var otherCrypto = CRYPTO_ISSUES.filter(function (c) { return c.fix !== G.crypto.fix; });
  G.remediation = {
    correct: [
      { text: G.controls.wouldHave, why: "Closes the way in. Nothing downstream gets a chance to matter." },
      { text: G.arch.fix, why: G.arch.why },
      { text: G.crypto.fix, why: G.crypto.why },
      { text: "Enforce MFA on " + G.iam.mfaGap,
        why: "The gap in the MFA posture is exactly where a stolen credential still works." }
    ],
    decoys: r.some(otherArch, 2).map(function (a) {
      return { text: a.fix, why: "Worth doing one day. It does not touch this breach — " + a.why.toLowerCase() };
    }).concat(r.some(otherCrypto, 2).map(function (c) {
      return { text: c.fix, why: "A real control for a finding this organisation does not have." };
    }))
  };

  /* ---- timeline the capstone rebuilds ---- */
  var tl = [];
  function ev(off, phase, what) { tl.push({ t: t0 + off, phase: phase, what: what }); }
  ev(0, "Detection & Analysis", (hand.human ? hand.human.label + " reaches " + victim.name : hand.tech.label + " against the estate"));
  ev(r.int(400, 1200), "Detection & Analysis", "Foothold established on " + victim.host);
  ev(r.int(1300, 2200), "Detection & Analysis", "Movement to " + extra.label + " using the " + over.label + " role");
  ev(r.int(2300, 3200), "Containment", reporter.name + " reports it to the service desk");
  ev(r.int(3300, 4200), "Eradication", "Account disabled and the host pulled from the network");
  tl.sort(function (a, b) { return a.t - b.t; });
  G.timeline = tl;

  return G;
}
