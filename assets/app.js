/* =====================================================================
   Security Awareness Center — page wiring

   Seven SY0-701 lenses on one generated breach, a tile where the student
   rebuilds the defences, and a capstone. Every graded answer is a function
   of the breach object, never a literal written beside the rows.
   ===================================================================== */
import { buildBreach, mulberry32, CONTROL_TYPES, CONTROL_CATS, IR_PHASES,
  VOLATILITY, PRINCIPLES, ALL_CLOCKS, ZONES, SERVICES, evaluateFlow, hhmm } from "./breach.js";
import { humanEvidence, indicatorRows, controlRows, responseRows } from "./evidence.js";

/* Every deadline any of the six organisations could be under, plus the ones
   students reach for by reflex. Built from the org table so it can never drift
   away from the answer. */
const CLOCKS = ALL_CLOCKS();

const PIN = "3693";
const SLOTS = 15;

let sessionSeed = Math.floor(Math.random() * 100000) + 1;
let slot = 1;
let G = null;
let instructor = false;
const graded = {};
let allQs = [];

const el = (t, c, h) => { const n = document.createElement(t); if (c) n.className = c; if (h !== undefined) n.innerHTML = h; return n; };
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const norm = (s) => String(s).trim().toLowerCase().replace(/\s+/g, " ");

/* Some questions have a correct answer that is the same string every time —
   "the system or data owner", "authority", and so on. Listed in source order
   those sit at option 1 in all fifteen scenarios, which is answerable without
   reading anything. Shuffle them deterministically off the scenario so the
   position moves per scenario but stays put while a student works. */
function ordShuffle(key, arr) {
  let h = (2166136261 ^ G.slot ^ (sessionSeed << 5)) >>> 0;
  for (let i = 0; i < key.length; i++) { h ^= key.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
  const rng = mulberry32(h);
  const x = arr.slice();
  for (let i = x.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const t = x[i]; x[i] = x[j]; x[j] = t;
  }
  return x;
}

function table(cols, rows, cell) {
  const w = el("div", "logwrap");
  const t = el("table", "log");
  t.innerHTML = "<thead><tr>" + cols.map((c) => `<th>${esc(c)}</th>`).join("") + "</tr></thead>";
  const tb = el("tbody");
  rows.forEach((r) => {
    const tr = el("tr");
    if (r._bad) tr.setAttribute("data-bad", "1");
    tr.innerHTML = cell(r);
    tb.appendChild(tr);
  });
  t.appendChild(tb); w.appendChild(t);
  const out = el("div");
  out.appendChild(w);
  // The log scrolls inside a fixed height, so the last visible row is often a
  // half row. Say how many there are, both as a scroll cue and because several
  // questions want a count. Only claim it scrolls once it actually overflows,
  // which is not knowable until the table has been laid out.
  const cap = el("p", "logcount", `${rows.length} entries`);
  out.appendChild(cap);
  requestAnimationFrame(() => {
    if (w.scrollHeight > w.clientHeight + 2) cap.innerHTML = `${rows.length} entries &mdash; scroll for the rest`;
  });
  return out;
}

/* ---------------- questions ---------------- */
function renderQuestions(host, qs, onGraded) {
  const box = el("div", "qs");
  qs.forEach((q) => {
    const card = el("div", "q");
    card.appendChild(el("p", "q__ask", q.ask));
    const row = el("div", "q__row");
    let input;
    if (q.kind === "choice") {
      const opts = q.shuffle ? ordShuffle(q.id, q.choices()) : q.choices();
      input = el("select", "ans");
      input.innerHTML = '<option value="">— select —</option>' +
        opts.map((c) => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
    } else {
      input = el("input"); input.type = "text";
      input.setAttribute("aria-label", q.ask.replace(/<[^>]+>/g, ""));
      if (q.placeholder) input.placeholder = q.placeholder;
    }
    const btn = el("button", "btn", "Check"); btn.type = "button";
    row.appendChild(input); row.appendChild(btn); card.appendChild(row);
    const fb = el("p", "fb"); fb.style.display = "none"; card.appendChild(fb);

    function check() {
      const val = input.value;
      if (!norm(val)) return;
      const ok = q.accept ? q.accept(val) : norm(val) === norm(q.answer());
      graded[q.id] = ok;
      if (q._answered) q._answered();
      fb.style.display = "";
      fb.className = "fb " + (ok ? "fb--ok" : "fb--no");
      fb.innerHTML = (ok ? "Correct" : "Not yet") + '<span class="fb__why">' + esc(q.why()) + "</span>";
      updateScore();
      if (onGraded) onGraded();
    }
    btn.addEventListener("click", check);
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); check(); } });
    /* Instructor mode paints the answer over whatever the card was showing.
       Turning it off has to put that back — blanking the card would delete a
       student's own graded answer along with the key, which is worse than
       leaving the key up. So remember what was underneath. */
    let revealed = false, beneath = null;
    q._reveal = () => {
      if (!revealed) beneath = { html: fb.innerHTML, cls: fb.className, disp: fb.style.display };
      revealed = true;
      fb.style.display = "";
      fb.className = "fb fb--ok";
      fb.innerHTML = "Answer: " + esc(q.answer()) +
        '<span class="fb__why">' + esc(q.why()) + "</span>";
    };
    q._unreveal = () => {
      if (!revealed) return;
      revealed = false;
      fb.innerHTML = beneath ? beneath.html : "";
      fb.className = beneath ? beneath.cls : "fb";
      fb.style.display = beneath ? beneath.disp : "none";
      beneath = null;
    };
    // Answering while the key is up makes the student's own result the state
    // the card falls back to, not the empty card it started as.
    q._answered = () => { revealed = false; beneath = null; };
    box.appendChild(card);
  });
  host.appendChild(box);
  return qs;
}

function updateScore() {
  const done = Object.keys(graded).length;
  const right = Object.keys(graded).filter((k) => graded[k]).length;
  document.getElementById("scorebar").innerHTML =
    `<span>Answered <b>${done}</b> of <b>${allQs.length}</b></span>` +
    `<span>Correct <b>${right}</b></span>` +
    `<span>Accuracy <b>${done ? Math.round((right / done) * 100) : 0}%</b></span>` +
    `<span>Scenario <b>${slot}</b> of ${SLOTS}</span>`;
  applyRemediationLock();
}

/* ---------------- hold-to-read key ---------------- */
function holdKey(labelText, entries) {
  const wrap = el("div");
  const btn = el("button", "btn btn--peek", labelText);
  btn.type = "button";
  btn.setAttribute("aria-expanded", "false");
  const panel = el("div", "gloss");
  panel.hidden = true;
  panel.innerHTML = entries.map(([k, v]) => `<div><b>${esc(k)}</b><span>${esc(v)}</span></div>`).join("");
  btn.setAttribute("aria-controls", panel.id = "key-" + Math.random().toString(36).slice(2, 8));
  let held = false;
  const show = (e) => { if (e) e.preventDefault(); held = true; panel.hidden = false; btn.setAttribute("aria-expanded", "true"); };
  const hide = () => { if (!held) return; held = false; panel.hidden = true; btn.setAttribute("aria-expanded", "false"); };
  btn.addEventListener("mousedown", show);
  btn.addEventListener("touchstart", show, { passive: false });
  ["mouseup", "mouseleave", "touchend", "touchcancel", "blur"].forEach((ev) => btn.addEventListener(ev, hide));
  btn.addEventListener("keydown", (e) => { if ((e.key === " " || e.key === "Enter") && !held) show(e); });
  btn.addEventListener("keyup", (e) => { if (e.key === " " || e.key === "Enter") hide(); });
  wrap.appendChild(btn); wrap.appendChild(panel);
  return wrap;
}

function tile(hue, num, title, intro) {
  const s = el("section", "tile tile--wide");
  s.setAttribute("data-hue", hue);
  const h = el("div", "tile__head");
  h.appendChild(el("span", "tile__num", num));
  h.appendChild(el("h2", null, esc(title)));
  s.appendChild(h);
  const b = el("div", "tile__body");
  if (intro) b.appendChild(el("p", "tile__intro", intro));
  s.appendChild(b);
  return { section: s, body: b };
}

/* ---- 0 · Human layer ---- */
function tileHuman() {
  const ev = humanEvidence(G);
  const t = tile("crimson", "Tile 0", "The human layer",
    ev.kind === "mail"
      ? (ev.channel === "Phone"
        ? "The switchboard log. One of these calls is the one that worked. Three people took it — only one did the right thing."
        : ev.channel === "SMS"
          ? "The message log from the mobile gateway. One of these is the one that worked. Three people got it — only one did the right thing."
          : "The mail log for the morning. One of these is the one that worked. Three people received it — only one did the right thing.")
      : ev.kind === "badge"
        ? "Door and visitor records. Somebody came through who should not have, and somebody watched it happen."
        : "Service desk activity. No message started this one, but people still made decisions worth grading.");

  if (ev.kind === "mail") {
    ev.rows.forEach((r) => { r._bad = /^(attack|bad)$/.test(r._t); });
    t.body.appendChild(table(["Time", ev.cols.from, ev.cols.to, ev.cols.subject, "Action"], ev.rows,
      (r) => `<td>${hhmm(r.t)}</td><td>${esc(r.from)}</td><td>${esc(r.to)}</td><td>${esc(r.subject)}</td><td>${esc(r.action)}</td>`));
  } else if (ev.kind === "badge") {
    ev.rows.forEach((r) => { r._bad = /^(attack|bad)$/.test(r._t); });
    t.body.appendChild(table(["Time", "Badge", "Person", "Door", "Result"], ev.rows,
      (r) => `<td>${hhmm(r.t)}</td><td>${esc(r.badge)}</td><td>${esc(r.who)}</td><td>${esc(r.door)}</td><td>${esc(r.result)}</td>`));
  } else {
    ev.rows.forEach((r) => { r._bad = /^(bad|good)$/.test(r._t); });
    t.body.appendChild(table(["Time", "Person", "Dept", "What happened", "Outcome"], ev.rows,
      (r) => `<td>${hhmm(r.t)}</td><td>${esc(r.who)}</td><td>${esc(r.dept)}</td><td>${esc(r.what)}</td><td>${esc(r.outcome)}</td>`));
  }

  // the tells — a pick-list, only shown when there is an approach to judge
  if (G.human) {
    /* A decoy has to be plainly ordinary, and it has to be about the same kind
       of event: message decoys on a tailgating scenario are answerable without
       thinking, and "sent outside core hours" is indistinguishable from the
       smishing tell that says exactly that. Each decoy carries the word that
       would make it collide, and any decoy colliding with a real tell is
       dropped before the three are dealt. */
    const pool = G.human.channel === "Physical"
      ? [["hours", "it happened during normal working hours"],
        ["busy", "reception was busy at the time"],
        ["jacket", "the person was wearing a high-visibility jacket"],
        ["carrying", "they were carrying something with both hands"],
        ["log", "the visitor log has other entries from the same day"],
        ["floor", "they were seen on more than one floor"]]
      : [["hours", "it was sent outside core hours"],
        ["first name", "the sender used the recipient's first name"],
        ["logo", "it carried the organisation's logo"],
        ["several", "it went to several people at once"],
        ["job title", "it was signed off with a job title"],
        ["system", "it referred to a real internal system by name"]];
    const tellText = G.human.tells.join(" ").toLowerCase();
    const decoys = ordShuffle("human-decoys", pool.filter((d) => tellText.indexOf(d[0]) === -1))
      .slice(0, 3).map((d) => d[1]);
    const items = ordShuffle("human-tells", G.human.tells.map((x) => ({ text: x, real: true }))
      .concat(decoys.map((x) => ({ text: x, real: false }))));
    const box = el("div", "picks");
    items.forEach((it, i) => {
      const lab = el("label", "pick");
      lab.setAttribute("data-real", it.real ? "1" : "0");
      lab.innerHTML = `<input type="checkbox" data-real="${it.real ? 1 : 0}"><span>${esc(it.text)}</span>`;
      box.appendChild(lab);
    });
    t.body.appendChild(el("p", "tile__intro", G.human.channel === "Physical"
      ? "<strong>Which of these are genuine indicators that this entry was not legitimate?</strong> Tick every one that holds up."
      : "<strong>Which of these are genuine indicators that this message was not what it claimed?</strong> Tick every one that holds up."));
    t.body.appendChild(box);
    const chk = el("button", "btn", "Check the tells"); chk.type = "button";
    chk.style.marginTop = ".6rem";
    const fb = el("p", "fb"); fb.style.display = "none";
    chk.addEventListener("click", () => {
      const boxes = [...box.querySelectorAll("input")];
      const ok = boxes.every((b) => b.checked === (b.dataset.real === "1"));
      graded["human-tells"] = ok;
      fb.style.display = "";
      fb.className = "fb " + (ok ? "fb--ok" : "fb--no");
      fb.innerHTML = (ok ? "Correct" : "Not yet") + '<span class="fb__why">' +
        esc("Real: " + G.human.tells.join("; ") + ". " + (G.human.channel === "Physical"
          ? "The rest describe an ordinary visitor. People carry boxes, reception gets busy, and contractors wear high-vis. A tell has to be something a legitimate visitor would not produce — a missing swipe, a door event with two bodies and one badge."
          : "The rest describe ordinary correspondence — plenty of legitimate messages arrive out of hours, use your first name, carry a logo and go to several people. A tell has to be something a genuine sender would not do.")) + "</span>";
      updateScore();
    });
    t.body.appendChild(chk); t.body.appendChild(fb);
  }

  const qs = [
    {
      id: "human-report", kind: "text", placeholder: "a name",
      ask: "Who did the right thing?",
      answer: () => G.reporter.name,
      accept: (v) => norm(v).indexOf(norm(G.reporter.name.split(" ")[1])) !== -1 || norm(v) === norm(G.reporter.name),
      why: () => `${G.reporter.name} reported it. Reporting is the control here — the whole point of awareness training is that one person escalating turns a compromise into an incident you know about.`
    },
    {
      id: "human-ignore", kind: "text", placeholder: "a name",
      ask: ev.kind === "badge"
        ? "Who watched an unbadged person come through and said nothing?"
        : ev.kind !== "mail"
          ? "Who clicked through a warning instead of reporting it?"
          : ev.channel === "Phone"
            ? "Who took the same call and did not report it?"
            : "Who got the same message and did not report it?",
      answer: () => G.ignorer.name,
      accept: (v) => norm(v).indexOf(norm(G.ignorer.name.split(" ")[1])) !== -1 || norm(v) === norm(G.ignorer.name),
      why: () => `${G.ignorer.name}. Nothing about that is a technical failure — the same evidence reached ${G.reporter.name}, who escalated it. That gap is what awareness training is for.`
    }
  ];

  if (G.human) {
    const wrong = ordShuffle("human-principle-d",
      Object.keys(PRINCIPLES).filter((k) => k !== G.human.principle)).slice(0, 3);
    qs.push({
      id: "human-principle", kind: "choice", shuffle: true,
      ask: "Which social-engineering principle is doing the work in this approach?",
      choices: () => [G.human.principle].concat(wrong).map((k) => PRINCIPLES[k]),
      answer: () => PRINCIPLES[G.human.principle],
      why: () => `${G.human.principle} — ${G.human.label.toLowerCase()} works through ${G.human.pretext}. The others are real principles; they are just not the lever here.`
    });
  }
  allQs = allQs.concat(renderQuestions(t.body, qs));
  return t.section;
}

/* ---- 1 · Threat ---- */
function tileThreat() {
  const t = tile("cyan", "Tile 1", "The threat",
    "Attribute the activity and separate real indicators from routine operations. Half of what looks alarming here is a well-run IT department doing its job.");

  const inds = indicatorRows(G);
  const box = el("div", "picks");
  inds.forEach((i) => {
    const lab = el("label", "pick");
    lab.setAttribute("data-real", i.real ? "1" : "0");
    lab.innerHTML = `<input type="checkbox" data-real="${i.real ? 1 : 0}"><span>${esc(i.ind)}</span>`;
    box.appendChild(lab);
  });
  t.body.appendChild(el("p", "tile__intro", "<strong>Tick every genuine indicator of malicious activity.</strong>"));
  t.body.appendChild(box);
  const chk = el("button", "btn", "Check the indicators"); chk.type = "button";
  chk.style.marginTop = ".6rem";
  const fb = el("p", "fb"); fb.style.display = "none";
  chk.addEventListener("click", () => {
    const boxes = [...box.querySelectorAll("input")];
    const ok = boxes.every((b) => b.checked === (b.dataset.real === "1"));
    graded["threat-inds"] = ok;
    fb.style.display = "";
    fb.className = "fb " + (ok ? "fb--ok" : "fb--no");
    fb.innerHTML = (ok ? "Correct" : "Not yet") + '<span class="fb__why">' +
      esc(inds.filter((i) => !i.real).map((i) => i.ind.split(" ").slice(0, 5).join(" ") + "… — " + i.why).join("  |  ")) + "</span>";
    updateScore();
  });
  t.body.appendChild(chk); t.body.appendChild(fb);

  const qs = [
    {
      id: "threat-actor", kind: "choice",
      ask: `Given the motive and the way this unfolded, which threat actor fits best?`,
      choices: () => ["Organized crime", "Nation-state", "Insider threat", "Hacktivist", "Unskilled attacker", "Shadow IT"],
      answer: () => G.actor.type,
      why: () => `${G.actor.type} — motive ${G.actor.motive.toLowerCase()}, sophistication ${G.actor.sophistication.toLowerCase()}, ${G.actor.funding.toLowerCase()}. The tell: it ${G.actor.tell}.`
    },
    {
      id: "threat-vector", kind: "choice",
      ask: "What was the threat vector — the route in?",
      choices: () => ["Phishing email", "Vishing call", "Smishing / SMS", "Business email compromise",
        "Tailgating", "Removable media drop", "Unpatched internet-facing service",
        "Third-party / supply chain", "Cloud misconfiguration", "Credential stuffing"],
      answer: () => G.entryLabel,
      why: () => `${G.entryLabel}. Vector is how they got in; the attack surface is what was exposed to be got in through. Keep the two apart — the exam does.`
    }
  ];
  allQs = allQs.concat(renderQuestions(t.body, qs));
  return t.section;
}

/* ---- 2 · Controls ---- */
function tileControls() {
  const rows = controlRows(G);
  const t = tile("amber", "Tile 2", "Controls",
    "The control inventory as it stood that morning. One control was present but the wrong kind for this job, and one that would have stopped it was never implemented.");
  rows.forEach((r) => { r._bad = /^(missing|wrong-kind)$/.test(r._t); });
  t.body.appendChild(table(["Control", "Type", "Category", "Status"], rows,
    (r) => `<td>${esc(r.name)}</td><td>${esc(r.type)}</td><td>${esc(r.cat)}</td><td>${esc(r.status)}</td>`));
  t.body.appendChild(holdKey("Hold for the control key",
    Object.keys(CONTROL_TYPES).map((k) => [k, CONTROL_TYPES[k]])
      .concat(Object.keys(CONTROL_CATS).map((k) => [k, CONTROL_CATS[k]]))));

  const qs = [
    {
      id: "ctl-missing", kind: "text", placeholder: "name the control",
      ask: "Which control would actually have prevented this?",
      answer: () => G.controls.wouldHave,
      accept: (v) => {
        const words = norm(G.controls.wouldHave).split(" ").filter((w) => w.length > 4);
        return words.some((w) => norm(v).indexOf(w) !== -1);
      },
      why: () => `${G.controls.wouldHave} — the only row marked NOT in place. ${G.controls.presentButWrong.name} was present, but ${G.controls.presentButWrong.why.toLowerCase()}`
    },
    {
      id: "ctl-cat", kind: "choice",
      ask: "Which category does that missing control belong to?",
      choices: () => Object.keys(CONTROL_CATS),
      answer: () => G.controls.correctCat,
      why: () => `${G.controls.correctCat} — ${CONTROL_CATS[G.controls.correctCat].toLowerCase()}. Its type is Preventive, because "would have prevented this" is what preventive means. Type and category are separate axes; every control has one of each.`
    },
    {
      id: "ctl-type", kind: "choice",
      ask: `And what type of control is “${esc(G.controls.presentButWrong.name)}” — the one that was in place and did not help?`,
      choices: () => Object.keys(CONTROL_TYPES),
      answer: () => G.controls.presentButWrong.type,
      why: () => `${G.controls.presentButWrong.type} — ${CONTROL_TYPES[G.controls.presentButWrong.type].toLowerCase()}. ${G.controls.presentButWrong.why} Having a control is not the same as having the right kind of control.`
    }
  ];
  allQs = allQs.concat(renderQuestions(t.body, qs));
  return t.section;
}

/* ---- 3 · Architecture ---- */
function tileArch() {
  const t = tile("green", "Tile 3", "Architecture",
    "Entry gets you one host. Architecture decides how far that host gets you. This is the design decision that turned a foothold into a breach.");
  t.body.appendChild(el("p", null, `<strong>Finding:</strong> ${esc(G.arch.gap)}`));
  t.body.appendChild(el("p", "count", `Objective ${esc(G.arch.domain)}`));

  const qs = [
    {
      id: "arch-fix", kind: "choice",
      ask: "Which architectural change addresses that finding?",
      choices: () => ["Segmentation", "Zero Trust", "Encryption at rest", "Offline / immutable backups",
        "Egress filtering", "Tested recovery site"],
      answer: () => G.arch.fix,
      why: () => `${G.arch.fix}. ${G.arch.why} The others are all real controls — they just do not answer this particular finding.`
    },
    {
      id: "arch-why", kind: "choice", shuffle: true,
      ask: "What did that gap actually cost you here?",
      choices: () => ["It let a single compromised foothold reach far more than it should have",
        "It made the initial phishing message more convincing",
        "It prevented the security team from being paged",
        "It caused the vulnerability itself"],
      answer: () => "It let a single compromised foothold reach far more than it should have",
      why: () => `Architecture does not stop you being phished. It decides the blast radius once you are. ${G.arch.why}`
    }
  ];
  allQs = allQs.concat(renderQuestions(t.body, qs));
  return t.section;
}

/* ---- 4 · Identity & crypto — the configure tile ---- */
function tileIdentity() {
  const t = tile("violet", "Tile 4", "Identity & crypto — configure it",
    "This one you build. Below is the current access matrix. Set each role to the minimum it needs to do its job, then check what your configuration permits. Strip too much and the business stops; leave too much and the breach spreads.");

  const res = G.iam.resources;
  const wrap = el("div", "matrix");
  const tb = el("table", "mx");
  tb.innerHTML = "<thead><tr><th>Role</th>" +
    res.map((x) => `<th>${esc(x.label)}</th>`).join("") + "</tr></thead>";
  const body = el("tbody");
  G.iam.roles.forEach((role) => {
    const tr = el("tr");
    let cells = `<td>${esc(role.label)}</td>`;
    res.forEach((x) => {
      const on = role.granted.indexOf(x.key) !== -1;
      const over = on && role.needs.indexOf(x.key) === -1;
      cells += `<td data-over="${over ? 1 : 0}"><input type="checkbox" data-role="${role.key}" data-res="${x.key}"${on ? " checked" : ""} aria-label="${esc(role.label)} — ${esc(x.label)}"></td>`;
    });
    tr.innerHTML = cells;
    body.appendChild(tr);
  });
  tb.appendChild(body); wrap.appendChild(tb);
  t.body.appendChild(wrap);

  const chk = el("button", "btn", "Check my configuration"); chk.type = "button";
  chk.style.marginTop = ".7rem";
  const fb = el("p", "fb"); fb.style.display = "none";
  chk.addEventListener("click", () => {
    const boxes = [...wrap.querySelectorAll("input")];
    let over = [], under = [];
    boxes.forEach((b) => {
      const role = G.iam.roles.find((r) => r.key === b.dataset.role);
      const needs = role.needs.indexOf(b.dataset.res) !== -1;
      if (b.checked && !needs) over.push(role.label + " → " + res.find((x) => x.key === b.dataset.res).label);
      if (!b.checked && needs) under.push(role.label + " → " + res.find((x) => x.key === b.dataset.res).label);
    });
    const ok = over.length === 0 && under.length === 0;
    graded["iam-config"] = ok;
    fb.style.display = "";
    fb.className = "fb " + (ok ? "fb--ok" : "fb--no");
    let msg;
    if (ok) {
      msg = `Least privilege. Removing ${G.iam.overGranted.label} → ${G.iam.extraLabel} is what closes this breach: that grant is how the attacker got from a foothold to ${G.iam.extraLabel.toLowerCase()}, and no one in that role needs it to work.`;
    } else {
      msg = (over.length ? "Still over-granted: " + over.join(", ") + ". " : "") +
        (under.length ? "You removed access the role genuinely needs: " + under.join(", ") + " — that breaks the business, which is not a security win. " : "") +
        "Least privilege is the minimum required to do the job, not the minimum possible.";
    }
    fb.innerHTML = (ok ? "Correct" : "Not yet") + '<span class="fb__why">' + esc(msg) + "</span>";
    updateScore();
  });
  t.body.appendChild(chk); t.body.appendChild(fb);

  t.body.appendChild(el("p", "mx-note",
    `<strong>MFA posture:</strong> ${esc(G.iam.mfa)}<br><strong>Cryptographic finding:</strong> ${esc(G.crypto.issue)}`));

  const qs = [
    {
      id: "iam-role", kind: "choice",
      ask: "Which role was over-granted?",
      choices: () => G.iam.roles.map((r) => r.label),
      answer: () => G.iam.overGranted.label,
      why: () => `${G.iam.overGranted.label} held ${G.iam.extraLabel}, which that job does not require. Privilege creep like this is usually granted once for a genuine reason and never taken back.`
    },
    {
      id: "crypto-fix", kind: "text", placeholder: "the remediation",
      ask: () => `The cryptographic finding is: <em>${esc(G.crypto.issue)}</em>. What fixes it?`,
      answer: () => G.crypto.fix,
      accept: (v) => {
        const words = norm(G.crypto.fix).split(/[ /()]+/).filter((w) => w.length > 3);
        return words.some((w) => norm(v).indexOf(w) !== -1);
      },
      why: () => `${G.crypto.fix}. ${G.crypto.why}`
    }
  ];
  // the crypto question's ask carries markup, so render it raw
  qs[1].ask = `The cryptographic finding is: <em>${esc(G.crypto.issue)}</em>. What fixes it?`;
  allQs = allQs.concat(renderQuestions(t.body, qs));
  return t.section;
}

/* ---- 5 · Response ---- */
function tileResponse() {
  const rows = responseRows(G);
  const t = tile("magenta", "Tile 5", "Response",
    "What the team actually did, in order. Five of these six actions were right. One of them cost you something you cannot get back.");
  rows.forEach((r) => { r._bad = r.ok === false; });
  t.body.appendChild(table(["Time", "Action", "IR phase", "Sound?"], rows,
    (r) => `<td>${hhmm(r.t)}</td><td>${esc(r.action)}</td><td>${esc(r.phase)}</td><td>${r.ok ? "yes" : "—"}</td>`));
  t.body.appendChild(holdKey("Hold for the IR phases & order of volatility",
    IR_PHASES.map((p, i) => [String(i + 1), p]).concat(
      [["—", "Order of volatility, most volatile first:"]],
      VOLATILITY.map((v, i) => [String(i + 1), v]))));

  const qs = [
    {
      id: "resp-miss", kind: "choice",
      ask: "Which action was the mistake?",
      choices: () => rows.map((r) => r.action),
      answer: () => G.respMiss.miss,
      why: () => `${G.respMiss.why}`
    },
    {
      id: "resp-phase", kind: "choice",
      ask: "Which incident response phase did that mistake belong to?",
      choices: () => IR_PHASES,
      answer: () => G.respMiss.phase,
      why: () => `${G.respMiss.phase}. Naming the phase matters because it tells you which playbook failed, not just which person did.`
    }
  ];
  allQs = allQs.concat(renderQuestions(t.body, qs));
  return t.section;
}

/* ---- 6 · Risk & compliance ---- */
function tileRisk() {
  const t = tile("blue", "Tile 6", "Risk & compliance",
    "The part that outlives the incident. Someone has to decide what happens next and who has to be told.");
  t.body.appendChild(el("p", null,
    `<strong>Assessment:</strong> likelihood ${esc(G.risk.likelihood)}, impact ${esc(G.risk.impact)} · ` +
    `roughly ${G.risk.records.toLocaleString()} records of ${esc(G.org.data)} in scope · ` +
    `organisational risk appetite is ${esc(G.risk.appetite)}`));
  t.body.appendChild(el("p", "count", `Regulatory context: ${esc(G.org.reg)} — ${esc(G.risk.regNote)}`));

  const qs = [
    {
      id: "risk-treat", kind: "choice",
      ask: "Which risk treatment fits this assessment?",
      choices: () => G.risk.options,
      answer: () => G.risk.correct,
      why: () => G.risk.correct === "Mitigate"
        ? `Mitigate. With impact ${G.risk.impact.toLowerCase()} against a ${G.risk.appetite} appetite, reducing it is the only defensible option. Transfer (insurance) moves the cost, not the risk; avoid would mean stopping the activity altogether; accept would put you outside your own appetite.`
        : `Accept. The impact sits inside a ${G.risk.appetite} appetite, and spending more to reduce it than it could cost you is not a security decision, it is a bad one. Document the acceptance and who owns it.`
    },
    {
      id: "risk-clock", kind: "choice", shuffle: true,
      ask: `Under ${esc(G.org.reg)}, how long do you have to notify?`,
      choices: () => CLOCKS.slice(),
      answer: () => G.risk.clock,
      why: () => `${G.risk.clock} — ${G.risk.regNote}. The clock is set by the regime the data sits under, not by how bad the incident feels. 72 hours is GDPR, and it gets applied to everything by people who have only learned one deadline.`
    },
    {
      id: "risk-owner", kind: "choice", shuffle: true,
      ask: "Who owns the decision to accept residual risk?",
      choices: () => ["The system or data owner in the business", "The SOC analyst who found it",
        "The third-party vendor", "Whoever is on call"],
      answer: () => "The system or data owner in the business",
      why: () => "Risk acceptance is a business decision with a named owner. Analysts surface risk and recommend; they do not own the acceptance — that separation is the whole point of governance."
    }
  ];
  allQs = allQs.concat(renderQuestions(t.body, qs));
  return t.section;
}

/* ---- 7 · Remediation — the build tile ----
   Locked until the threat is identified, because the whole point is that you
   fix what you have diagnosed rather than reaching for controls you happen to
   like. Everything here is graded by replaying the breach against whatever the
   student configured, so the feedback is "your rules still let it through",
   not "that is not the answer I wanted". */
function tileRemediation() {
  const t = tile("orange", "Tile 7", "Remediation — build the fix",
    "You have named it. Now close it. Repair the firewall, then fund the changes that address this breach and only this breach.");

  const lock = el("div", "lockbox");
  lock.innerHTML = "<strong>Locked.</strong> Answer the threat tile first — the vector and the actor. " +
    "You cannot fix a hole you have not identified, and this tile will not let you guess your way to one.";
  t.body.appendChild(lock);

  const work = el("div", "remwork");
  t.body.appendChild(work);

  /* ---------- 1 · the firewall ---------- */
  work.appendChild(el("p", "tile__intro",
    "<strong>1 · The perimeter and internal firewall.</strong> Rules are evaluated top to bottom, " +
    "first match wins, and anything that matches nothing is denied. The rule set below is the one " +
    "that was running this morning."));

  let rules = G.net.startRules.map((r) => Object.assign({}, r));

  const fwWrap = el("div", "fw");
  const fwBody = el("div");
  fwWrap.appendChild(fwBody);
  work.appendChild(fwWrap);

  const sel = (val, opts, cls, onchange) => {
    const s = el("select", cls);
    s.innerHTML = Object.keys(opts).map((k) =>
      `<option value="${esc(k)}"${k === val ? " selected" : ""}>${esc(opts[k])}</option>`).join("");
    s.addEventListener("change", onchange);
    return s;
  };
  const ZONE_OPTS = Object.assign({ any: "Any zone" }, ZONES);
  const SVC_OPTS = Object.assign({ any: "Any service" }, SERVICES);
  const ACT_OPTS = { allow: "ALLOW", deny: "DENY" };

  function drawRules() {
    fwBody.innerHTML = "";
    const head = el("div", "fw__row fw__row--head");
    head.innerHTML = "<span>#</span><span>Action</span><span>Source</span><span>Destination</span>" +
      "<span>Service</span><span>Order</span>";
    fwBody.appendChild(head);

    rules.forEach((r, i) => {
      const row = el("div", "fw__row");
      row.appendChild(el("span", "fw__n", String(i + 1)));
      // Update in place rather than redrawing. A redraw here would throw away
      // keyboard focus mid-edit, and it repaints the other three selects in the
      // row from the model, so anything typed into them in the same tick is
      // lost from the display even though the model kept it.
      const a = sel(r.action, ACT_OPTS, "fw__act", (e) => {
        r.action = e.target.value;
        e.target.dataset.act = r.action;
      });
      a.setAttribute("aria-label", "Rule " + (i + 1) + " action");
      a.dataset.act = r.action;
      row.appendChild(a);
      const s1 = sel(r.src, ZONE_OPTS, null, (e) => { r.src = e.target.value; });
      s1.setAttribute("aria-label", "Rule " + (i + 1) + " source");
      row.appendChild(s1);
      const s2 = sel(r.dst, ZONE_OPTS, null, (e) => { r.dst = e.target.value; });
      s2.setAttribute("aria-label", "Rule " + (i + 1) + " destination");
      row.appendChild(s2);
      const s3 = sel(r.svc, SVC_OPTS, null, (e) => { r.svc = e.target.value; });
      s3.setAttribute("aria-label", "Rule " + (i + 1) + " service");
      row.appendChild(s3);

      const ctl = el("span", "fw__ctl");
      const mk = (label, aria, fn, on) => {
        const btn = el("button", "fw__btn", label);
        btn.type = "button"; btn.setAttribute("aria-label", aria + " rule " + (i + 1));
        btn.disabled = !on;
        btn.addEventListener("click", fn);
        return btn;
      };
      ctl.appendChild(mk("&uarr;", "Move up", () => {
        rules.splice(i - 1, 0, rules.splice(i, 1)[0]); drawRules();
      }, i > 0));
      ctl.appendChild(mk("&darr;", "Move down", () => {
        rules.splice(i + 1, 0, rules.splice(i, 1)[0]); drawRules();
      }, i < rules.length - 1));
      ctl.appendChild(mk("&times;", "Delete", () => { rules.splice(i, 1); drawRules(); }, true));
      row.appendChild(ctl);
      if (r.note) {
        const n = el("span", "fw__note", esc(r.note));
        row.appendChild(n);
      }
      fwBody.appendChild(row);
    });

    const tail = el("div", "fw__row fw__row--tail");
    tail.innerHTML = "<span>&mdash;</span><span>DENY</span><span>Any zone</span><span>Any zone</span>" +
      "<span>Any service</span><span>implicit</span>";
    fwBody.appendChild(tail);
  }
  drawRules();

  const addBtn = el("button", "btn", "+ Add rule"); addBtn.type = "button";
  addBtn.style.marginTop = ".6rem";
  addBtn.addEventListener("click", () => {
    rules.push({ action: "allow", src: "user", dst: "internet", svc: "web" });
    drawRules();
  });
  const resetBtn = el("button", "btn btn--peek", "Reset to this morning's rules"); resetBtn.type = "button";
  resetBtn.style.marginTop = ".6rem"; resetBtn.style.marginLeft = ".4rem"; resetBtn.style.cursor = "pointer";
  resetBtn.addEventListener("click", () => {
    rules = G.net.startRules.map((r) => Object.assign({}, r)); drawRules();
  });
  const btnRow = el("div");
  btnRow.appendChild(addBtn); btnRow.appendChild(resetBtn);
  work.appendChild(btnRow);

  const testBtn = el("button", "btn", "Run the traffic test"); testBtn.type = "button";
  testBtn.style.marginTop = ".7rem";
  const fwFb = el("p", "fb"); fwFb.style.display = "none";
  const fwOut = el("div");
  testBtn.addEventListener("click", () => {
    const results = G.net.flows.map((f) => {
      const v = evaluateFlow(rules, f);
      return { f: f, got: v.allowed, rule: v.rule, ok: v.allowed === f.allow };
    });
    const ok = results.every((r) => r.ok);
    graded["fw-rules"] = ok;
    fwOut.innerHTML = "";
    fwOut.appendChild(table(["Traffic", "Should be", "Your rules", "Matched"], results.map((r) => ({
      _bad: !r.ok, l: r.f.label,
      want: r.f.allow ? "allowed" : "denied",
      got: r.got ? "allowed" : "denied",
      rule: r.rule ? "rule " + r.rule : "implicit deny",
      ok: r.ok
    })), (r) => `<td>${esc(r.l)}</td><td>${esc(r.want)}</td>` +
      `<td>${r.ok ? "✓" : "✗"} ${esc(r.got)}</td><td>${esc(r.rule)}</td>`));
    fwFb.style.display = "";
    fwFb.className = "fb " + (ok ? "fb--ok" : "fb--no");
    const wrongDeny = results.filter((r) => !r.ok && r.f.allow);
    const wrongAllow = results.filter((r) => !r.ok && !r.f.allow);
    fwFb.innerHTML = (ok ? "Correct" : "Not yet") + '<span class="fb__why">' + esc(ok
      ? "The breach traffic is denied and every legitimate flow still works. Note what you did not do: you did not deny the user VLAN outright. Least privilege on a firewall is the same idea as least privilege on an account — the minimum that lets the job happen."
      : (wrongAllow.length ? "Still getting through: " + wrongAllow.map((r) => r.f.label).join("; ") + ". " : "") +
        (wrongDeny.length ? "You have broken the business: " + wrongDeny.map((r) => r.f.label).join("; ") + " should still work. " : "") +
        "Remember first match wins — a broad deny above a narrow allow swallows it.") + "</span>";
    updateScore();
  });
  work.appendChild(testBtn);
  work.appendChild(fwFb);
  work.appendChild(fwOut);

  /* ---------- 2 · everything else ---------- */
  work.appendChild(el("p", "tile__intro",
    "<strong>2 · The rest of the fix.</strong> A budget was released this morning. " +
    "Tick every change that addresses <em>this</em> breach, and leave the ones that do not. " +
    "Some of these are good controls for an incident you did not have."));

  const items = ordShuffle("remediation",
    G.remediation.correct.map((x) => ({ text: x.text, why: x.why, real: true }))
      .concat(G.remediation.decoys.map((x) => ({ text: x.text, why: x.why, real: false }))));
  const box = el("div", "picks");
  items.forEach((it) => {
    const lab = el("label", "pick");
    lab.setAttribute("data-real", it.real ? "1" : "0");
    lab.innerHTML = `<input type="checkbox" data-real="${it.real ? 1 : 0}"><span>${esc(it.text)}</span>`;
    box.appendChild(lab);
  });
  work.appendChild(box);

  const remBtn = el("button", "btn", "Commit the remediation plan"); remBtn.type = "button";
  remBtn.style.marginTop = ".6rem";
  const remFb = el("p", "fb"); remFb.style.display = "none";
  remBtn.addEventListener("click", () => {
    const boxes = [...box.querySelectorAll("input")];
    const ok = boxes.every((b) => b.checked === (b.dataset.real === "1"));
    graded["rem-plan"] = ok;
    remFb.style.display = "";
    remFb.className = "fb " + (ok ? "fb--ok" : "fb--no");
    remFb.innerHTML = (ok ? "Correct" : "Not yet") + '<span class="fb__why">' +
      esc(items.filter((i) => i.real).map((i) => i.text + " — " + i.why).join("  |  ") +
        "  ||  Left alone: " + items.filter((i) => !i.real).map((i) => i.text).join("; ") +
        ". Funding a control that does not address the incident you just had is how a security budget " +
        "gets spent without the risk moving.") + "</span>";
    updateScore();
  });
  work.appendChild(remBtn);
  work.appendChild(remFb);

  return t.section;
}

/* The remediation tile opens once the threat tile has been answered. */
function applyRemediationLock() {
  const sec = document.querySelector('.tile[data-hue="orange"]');
  if (!sec) return;
  const open = instructor || (graded["threat-vector"] === true && graded["threat-actor"] === true);
  sec.classList.toggle("tile--locked", !open);
  const box = sec.querySelector(".lockbox");
  if (box) box.hidden = open;
}

/* ---- capstone ---- */
function tileCapstone() {
  const t = tile("teal", "Capstone", "The write-up",
    "One breach, seven lenses and a rebuild. Account for it: how it started, why it spread, and the one change that would have mattered most.");

  const qs = [
    {
      id: "cap-chain", kind: "choice", shuffle: true,
      ask: "In one line — what is the causal chain?",
      choices: () => [
        `${G.entryLabel} → foothold → over-granted ${G.iam.overGranted.label} role → ${G.iam.extraLabel}`,
        `Unpatched server → ransomware → backups encrypted`,
        `Insider copied data to personal storage → no exfiltration path needed`,
        `Vendor breach → shared credentials → domain compromise`
      ],
      answer: () => `${G.entryLabel} → foothold → over-granted ${G.iam.overGranted.label} role → ${G.iam.extraLabel}`,
      why: () => `Entry got them one account. The over-granted ${G.iam.overGranted.label} role is what carried them to ${G.iam.extraLabel}, and the architecture gap (${G.arch.gap.split("—")[0].trim().toLowerCase()}) is why nothing stood in the way.`
    },
    {
      id: "cap-one", kind: "choice", shuffle: true,
      ask: "If you could fund exactly one change, which buys the most?",
      choices: () => [G.controls.wouldHave, G.arch.fix, G.crypto.fix, "More frequent awareness training"],
      answer: () => G.controls.wouldHave,
      why: () => `${G.controls.wouldHave} — it stops the entry outright, so nothing downstream gets a chance to matter. ${G.arch.fix} and ${G.crypto.fix} both reduce the damage after the fact, and they are worth doing; they are the second and third cheque, not the first.`
    },
    {
      id: "cap-report", kind: "choice", shuffle: true,
      ask: "What goes in the lessons-learned that is not a technology change?",
      choices: () => [
        `${G.reporter.name} reported it and that is what surfaced it — make that behaviour the norm`,
        "Buy a different endpoint product",
        "Increase the firewall rule count",
        "Nothing — the technology failed, not the people"
      ],
      answer: () => `${G.reporter.name} reported it and that is what surfaced it — make that behaviour the norm`,
      why: () => `${G.ignorer.name} saw something and said nothing; ${G.reporter.name} said something. The difference between those two is culture, and it is the cheapest control on this page.`
    }
  ];
  allQs = allQs.concat(renderQuestions(t.body, qs));

  const tlWrap = el("div");
  tlWrap.id = "capTimeline";
  tlWrap.hidden = true;
  tlWrap.appendChild(el("p", "tile__intro", "<strong>How it actually ran</strong>"));
  tlWrap.appendChild(table(["Time", "Phase", "What happened"], G.timeline,
    (r) => `<td>${hhmm(r.t)}</td><td>${esc(r.phase)}</td><td>${esc(r.what)}</td>`));
  t.body.appendChild(tlWrap);
  return t.section;
}

/* ---------------- render ---------------- */
function render() {
  G = buildBreach(sessionSeed, slot);
  allQs = [];
  Object.keys(graded).forEach((k) => delete graded[k]);

  document.getElementById("brief").innerHTML =
    `<strong>Scenario ${slot}</strong> · ${esc(G.org.name)} — a breach was confirmed this morning. ` +
    `Work the seven lenses below, close the holes, then write it up.`;

  const host = document.getElementById("tiles");
  host.innerHTML = "";
  [tileHuman(), tileThreat(), tileControls(), tileArch(), tileIdentity(), tileResponse(),
    tileRisk(), tileRemediation()].forEach((s) => host.appendChild(s));
  const cap = document.getElementById("capstone");
  cap.innerHTML = "";
  cap.appendChild(tileCapstone());

  // the two pick-lists are graded but rendered outside renderQuestions
  allQs = allQs.concat([{ id: "threat-inds" }]);
  if (G.human) allQs = allQs.concat([{ id: "human-tells" }]);
  allQs = allQs.concat([{ id: "iam-config" }, { id: "fw-rules" }, { id: "rem-plan" }]);

  applyInstructor();
  updateScore();
}

function applyInstructor() {
  document.body.classList.toggle("reveal", instructor);
  applyRemediationLock();
  const tl = document.getElementById("capTimeline");
  if (tl) tl.hidden = !instructor;
  allQs.forEach((q) => {
    if (instructor) { if (q._reveal) q._reveal(); }
    else if (q._unreveal) q._unreveal();
  });
}

/* ---------------- chrome ---------------- */
const sel = document.getElementById("slotSelect");
for (let i = 1; i <= SLOTS; i++) {
  const o = document.createElement("option");
  o.value = String(i); o.textContent = "Scenario " + i;
  sel.appendChild(o);
}
sel.addEventListener("change", () => { slot = parseInt(sel.value, 10); render(); });
document.getElementById("shuffleBtn").addEventListener("click", () => {
  sessionSeed = Math.floor(Math.random() * 100000) + 1;
  render();
});

const ov = document.getElementById("pinOverlay");
const pinInput = document.getElementById("pinInput");
const pinErr = document.getElementById("pinErr");
const insBtn = document.getElementById("instructorBtn");
function closePin() { ov.classList.add("hidden"); pinInput.value = ""; pinErr.style.display = "none"; }
insBtn.addEventListener("click", () => {
  if (instructor) { instructor = false; insBtn.textContent = "Instructor mode"; applyInstructor(); return; }
  ov.classList.remove("hidden"); pinInput.focus();
});
document.getElementById("pinCancel").addEventListener("click", closePin);
document.getElementById("pinOk").addEventListener("click", tryPin);
pinInput.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); tryPin(); } });
ov.addEventListener("click", (e) => { if (e.target === ov) closePin(); });
function tryPin() {
  if (pinInput.value.trim() === PIN) {
    instructor = true; insBtn.textContent = "Instructor mode: on";
    closePin(); applyInstructor();
  } else { pinErr.style.display = ""; pinErr.textContent = "Wrong PIN."; }
}

(function () {
  const root = document.documentElement;
  const btn = document.getElementById("themeBtn");
  const KEY = "secaware-theme";
  const sys = () => window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  function apply(th) {
    root.setAttribute("data-theme", th);
    btn.textContent = th === "light" ? "Light" : "Dark";
    btn.setAttribute("aria-pressed", th === "light" ? "true" : "false");
    try { localStorage.setItem(KEY, th); } catch (e) { /* storage unavailable */ }
  }
  let saved = null;
  try { saved = localStorage.getItem(KEY); } catch (e) { /* storage unavailable */ }
  apply(saved === "light" || saved === "dark" ? saved : (root.getAttribute("data-theme") || sys()));
  btn.addEventListener("click", () => apply(root.getAttribute("data-theme") === "light" ? "dark" : "light"));
})();

render();
