/* =====================================================================
   Guided hints

   Nothing appears for the first two wrong answers. A student one guess from
   it should be allowed to get there on their own, and a page that starts
   helping the moment somebody is wrong teaches them to guess and wait.

   From the third wrong answer, one rung per attempt, escalating. Every rung
   obeys the same rule: NEVER the answer, and never a shortlist so narrow
   that the answer falls out of it. What they give is what a good instructor
   gives — which panel actually settles it, how to reason over it, and which
   tempting reading to rule out and why.

   Generated rather than tabulated, keyed off the question id. A table of
   hand-written hints stops growing the moment a question is added; this
   gives a new question a working ladder on the day it is written.
   ===================================================================== */

/* Which lens a question belongs to, from its id prefix — which is how the
   ids were already named. */
function lensOf(id) {
  const p = String(id).split("-")[0];
  return ["threat", "human", "ctl", "iam", "crypto", "arch", "fw", "resp", "risk", "rem", "cap"]
    .indexOf(p) === -1 ? "cap" : p;
}

/* Where the evidence for this lens lives on the page. */
const WHERE = {
  threat: "the intrusion narrative and the indicator list — what was actually observed, not what it implies",
  human: "the message itself, word by word, and what the recipient did next",
  ctl: "the control inventory, one row at a time, including the status column",
  iam: "the account and role listing, and what each one was actually permitted to do",
  crypto: "how the data was protected at each point it moved or sat still",
  arch: "the network layout and where the trust boundaries actually fall",
  fw: "the rule table — every rule in it is a real rule doing a real job for somebody",
  resp: "the response timeline, and which phase each action belongs to",
  risk: "the risk register entries, their owners and their dates",
  rem: "the remediation options and what each one costs against what it buys",
  cap: "your own answers in the lenses above. This is the accounting, not a fresh investigation"
};

/* The reasoning move, per kind of question. */
const HOW = {
  observe: "Split what you have into two piles: what was OBSERVED, and what was CONCLUDED. An indicator " +
    "is something a log could have recorded. An attribution is somebody's inference about it.",
  tells: "Stop looking for the thing that feels wrong and start listing what the message ASKS for. " +
    "Pressure, secrecy, a deadline, an unusual channel — the tells are demands, not typos.",
  principle: "Ask what the message was leaning on to make a reasonable person act against their training. " +
    "Name the lever, not the emotion it produced.",
  classify: "Categories here are about WHEN a control acts and HOW it acts — before, during, or after, " +
    "and by technology, by process, or by a person. Place it on both axes before you answer.",
  gap: "Do not look for the control that failed. Look for the one that was never there, by walking the " +
    "attack forward and asking what would have stopped it at each step.",
  config: "Read what the account could actually DO, not what it was called. A name is a label; a " +
    "permission is a fact.",
  rule: "Read every rule as though somebody depends on it, because somebody does. The question is which " +
    "single change stops this attack without breaking a real job.",
  phase: "Work from the action to the phase it belongs to, not from the phase you expect to see. " +
    "Containment, eradication and recovery are different jobs and get done in that order.",
  own: "Risk ownership follows the person who can accept the consequence, not the person who noticed it " +
    "and not the person who will do the work.",
  treat: "There are only a few things you can do with a risk, and they are not interchangeable. Ask what " +
    "actually happens to the exposure under each one.",
  plan: "A remediation has to address THIS cause. Read each option and ask whether it would have stopped " +
    "this exact incident, or whether it is just good practice that happens to be true.",
  report: "Write for the person who reads this knowing nothing and has to decide something. What would " +
    "they need in order to trust your conclusion rather than just repeat it?"
};

function askKind(id) {
  if (/threat-(inds|vector)/.test(id)) return "observe";
  if (/threat-actor/.test(id)) return "observe";
  if (/human-tells/.test(id)) return "tells";
  if (/human-(principle|ignore)/.test(id)) return "principle";
  if (/human-report|cap-report/.test(id)) return "report";
  if (/ctl-(cat|type)/.test(id)) return "classify";
  if (/ctl-missing|cap-one/.test(id)) return "gap";
  if (/iam-|crypto-|arch-why/.test(id)) return "config";
  if (/fw-rules/.test(id)) return "rule";
  if (/resp-/.test(id)) return "phase";
  if (/risk-owner/.test(id)) return "own";
  if (/risk-(treat|clock)/.test(id)) return "treat";
  if (/rem-plan|arch-fix|crypto-fix/.test(id)) return "plan";
  if (/cap-/.test(id)) return "report";
  return "observe";
}

/* WHERE TO LOOK, once the hints are spent.

   Two cases, and the second matters. Most questions here are settled by a
   panel in their own lens. Some are not: what to report, how to treat a
   risk, who owns it, what to plan. Those are decisions about people and
   consequences, and marking the nearest table would be a lie dressed as
   help — a student who followed it would hunt for a row that does not
   exist. Those say so instead. */
export function lookTarget(id) {
  const kind = askKind(id);
  if (kind === "report" || kind === "treat" || kind === "own" || kind === "plan") return "none";
  return "evidence";
}

export const LOOK_LABEL = {
  evidence: "The answer is in what is marked, not in the options. Read it again before you pick.",
  none: "Nothing on this page will settle this one — that is why nothing is marked. It is a decision " +
    "about people and consequences, answered from what you have already established."
};

export function questionHints(id) {
  const kind = askKind(id);
  const lens = lensOf(id);
  const out = [];

  out.push(kind === "report" || kind === "treat" || kind === "own" || kind === "plan"
    ? "Re-reading the panels will not settle this one. It is a judgement about what you already have, " +
      "so think about who is affected and who has to decide."
    : "Go back and read " + WHERE[lens] + ". Almost every wrong answer here is one given before the " +
      "panel was read properly.");

  out.push(HOW[kind] || HOW.observe);

  /* The strongest rung: the trap this lens was built around. Naming the trap
     is fair guidance — it still does not say which option is right. */
  const TRAP = {
    threat: "Rule one thing out: the country. Where infrastructure sits is not who is behind it, and an " +
      "indicator is not an attribution.",
    human: "Rule one thing out: spelling. Convincing messages are well written, and looking for typos is " +
      "the habit that gets people caught. Ask what it wanted them to DO.",
    ctl: "Rule one thing out: the control that is present. One of them is in place and is simply the wrong " +
      "kind for this job — present is not the same as effective.",
    iam: "Rule one thing out: the job title. What an account was permitted to do is the fact; what it was " +
      "called is decoration.",
    crypto: "Rule one thing out: 'it was encrypted'. Ask where it was encrypted, and where it was not.",
    arch: "Rule one thing out: the firewall at the edge. Ask what the layout allows once something is " +
      "already inside it.",
    fw: "Rule one thing out: deleting the rule that looks alarming. Every rule in that table is doing a " +
      "real job for somebody, and breaking the business is a failure too.",
    resp: "Rule one thing out: doing the satisfying thing first. Wiping the machine before you understand " +
      "the intrusion destroys the evidence you still need.",
    risk: "Rule one thing out: the person who found it. Noticing a risk is not owning it.",
    rem: "Rule one thing out: the fix that is good practice but would not have stopped THIS. Read each " +
      "option against the actual cause.",
    cap: "Rule one thing out: the tidy answer. The honest scope is usually wider than the set of machines " +
      "anybody touched."
  };
  if (TRAP[lens]) out.push(TRAP[lens]);
  return out;
}
