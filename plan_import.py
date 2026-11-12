"""Read a Call Coaching program (.docx) into the app's plan + nutrition format.

The program docs follow one layout:
  Title line "Name — Training & Nutrition Program"
  Heading "STRENGTH TRAINING": "Monday — Focus" lines, "Warm-Up (x min): a; b", "Main Work …",
     exercise lines, "Cool-Down (x min): a; b", then "Tempo:/Progression:/Joint watch:" notes
  Heading "CARDIO": "Mon/Thu: 20 min …" lines
  Heading "FLEXIBILITY & MOBILITY": "Daily 10-min routine (Mon/Tue/Thu/Fri…):" + items,
     "Wednesday full session (20 min): …", "Sunday recovery (15 min): …"
  Heading "NUTRITION": target, macros, "Breakfast — ~320 cal, 28g protein" + items, variety, notes
"""
import io
import re

WEEK = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
AB = [d[:3] for d in WEEK]
DASH = r"\s*[—–-]{1,2}\s*"


def days_in(spec: str):
    """'Mon/Thu', 'Mon-Thu, post-workout', 'Sun (optional)' -> ['Monday', ...]"""
    out = []
    for a, b in re.findall(r"\b(Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*(?:\s*-\s*(Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*)?", spec):
        i = AB.index(a)
        j = AB.index(b) if b else i
        out += WEEK[i:j + 1] if j >= i else WEEK[i:] + WEEK[:j + 1]
    return out


def split_parens(name: str):
    """'Leg Press (limited, pain-free depth)' -> ('Leg Press', 'limited, pain-free depth')"""
    notes = re.findall(r"\(([^)]*)\)", name)
    clean = re.sub(r"\s*\([^)]*\)", "", name).strip()
    return clean, "; ".join(n.strip() for n in notes if n.strip())


def unit_of(reps: str):
    r = reps.lower()
    if re.search(r"\bsec", r):
        return "sec"
    if re.search(r"\b(yds|yards|meters)\b", r):
        return "yds"
    return "reps"


def parse_item(text: str):
    """'Face Pulls x15' / 'Plank x30-45 sec' / "Farmer's Carry 30-40 yds (moderate load)" -> (name, reps, cue)"""
    text = text.strip().rstrip(".")
    m = None
    for m in re.finditer(r"\s+x\s*(?=max\b|\d)", text):
        pass
    if m:
        name, reps = text[:m.start()], text[m.end():]
    else:
        d = re.match(r"^(.+?)\s+(\d[\d\-–.]*\s*(?:yds|yards|meters|m|sec|seconds|min)\b.*)$", text)
        name, reps = (d.group(1), d.group(2)) if d else (text, "")
    reps, rnote = split_parens(reps)
    name, nnote = split_parens(name)
    cue = "; ".join(x for x in (nnote, rnote) if x)
    return name.strip(), reps.strip(), cue


def ex(group, name, sets, reps, cue=""):
    reps = reps or "as prescribed"
    return {"group": group, "name": name[:80], "scheme": f"{sets} × {reps}"[:40], "sets": max(1, min(int(sets), 10)),
            "unit": unit_of(reps), "cue": cue[:300], "demo": ""}


GROUP_LINE = re.compile(
    r"^(?P<label>Superset\s+(?P<letter>[A-Z])|Core finisher|Core finish|Core|Finisher)\s*"
    r"(?:[—–-]+\s*(?P<r1>\d+)\s*rounds?|\((?P<r2>\d+)\s*rounds?[^)]*\))\s*:\s*(?P<items>.+)$", re.I)
STRAIGHT = re.compile(r"^(?P<name>.+?)" + DASH + r"(?P<sets>\d+)\s*x\s*(?P<reps>.+)$")
PAIR = re.compile(r"^(?P<g>[A-Z])1:\s*(?P<a>.+?)\s*/\s*(?P=g)\s?2:\s*(?P<b>.+)$")
DAY_HEAD = re.compile(r"^(?P<day>" + "|".join(WEEK) + r")" + DASH + r"(?P<name>.+)$")


def parse_exercise_line(t: str, default_sets: int):
    """Returns a list of exercise dicts for one line, or None if the line isn't an exercise line."""
    m = PAIR.match(t)
    if m:
        out = []
        for part in (m["a"], m["b"]):
            n, r, c = parse_item(part)
            out.append(ex(m["g"], n, default_sets, r, c))
        return out
    m = GROUP_LINE.match(t)
    if m:
        rounds = int(m["r1"] or m["r2"])
        label = m["letter"].upper() if m["letter"] else ("Finisher" if m["label"].lower() == "finisher" else "Core")
        items = [x for x in re.split(r"\s+/\s+", m["items"]) if x.strip()]
        if len(items) == 1:
            items = [x for x in re.split(r",\s+(?=[A-Z])", m["items"]) if x.strip()]
        return [ex(label, *_nrc(i, rounds)) for i in items]
    m = STRAIGHT.match(t)
    if m:
        name, cue = split_parens(m["name"])
        reps, note = split_parens(m["reps"])
        note = re.sub(r"straight sets,?\s*", "", note, flags=re.I).strip(" ,;")
        cue = "; ".join(x for x in (cue, note) if x)
        return [ex("", name, int(m["sets"]), reps, cue)]
    return None


def _nrc(item, rounds):
    n, r, c = parse_item(item)
    return n, rounds, r, c


def num(s):
    m = re.search(r"(\d[\d,]*)", s or "")
    return int(m.group(1).replace(",", "")) if m else 0


def parse_docx(data: bytes):
    import docx  # python-docx

    doc = docx.Document(io.BytesIO(data))
    paras = [(p.style.name if p.style is not None else "", p.text.strip()) for p in doc.paragraphs]
    paras = [(s, t) for s, t in paras if t]
    title = paras[0][1] if paras else ""
    who = re.split(DASH, title)[0].strip() if title else ""

    section = ""
    days = {}  # weekday -> day
    order = []
    cur = None
    default_sets = 3
    notes = []
    cardio = {}  # weekday -> [items]
    move = {}
    routine_days = None
    nut = {"targets": {}, "meals": [], "notes": [], "swaps": []}
    nsub = ""
    meal = None

    for style, t in paras:
        if style.startswith("Heading"):
            u = t.upper()
            section = ("strength" if "STRENGTH" in u else "cardio" if "CARDIO" in u
                       else "mobility" if "MOBIL" in u or "FLEXIB" in u else "nutrition" if "NUTRITION" in u else "")
            cur, routine_days, nsub, meal = None, None, "", None
            continue
        is_list = style.lower().startswith("list")

        if section == "strength":
            m = DAY_HEAD.match(t)
            if m and not is_list:
                cur = {"weekday": m["day"], "name": m["name"].strip()[:80], "warmup": [], "warmup_label": "",
                       "cooldown": [], "cooldown_label": "", "note": "", "exercises": [], "condition": [], "move": []}
                days[m["day"]] = cur
                order.append(m["day"])
                default_sets = 3
                continue
            m = re.match(r"^(Warm[- ]?Up|Cool[- ]?Down)\s*(?:\(([^)]*)\))?\s*:\s*(.+)$", t, re.I)
            if m and cur:
                key = "warmup" if m.group(1).lower().startswith("warm") else "cooldown"
                cur[key] = [x.strip().rstrip(".") for x in re.split(r";\s*", m.group(3)) if x.strip()][:15]
                cur[key + "_label"] = (m.group(2) or "").strip()
                continue
            if re.match(r"^Main Work", t, re.I):
                r = re.search(r"(\d+)\s*rounds", t)
                default_sets = int(r.group(1)) if r else 3
                continue
            lab = re.match(r"^(Tempo|Progression|Joint watch|Form|Rest)\b[^:]{0,40}:\s*(.+)$", t, re.I)
            if lab and not is_list:
                notes.append(t[:600])
                continue
            if cur is not None:
                got = parse_exercise_line(t, default_sets)
                if got:
                    cur["exercises"] += got
                    continue
                if not is_list and not cur["exercises"] and not cur["warmup"]:
                    cur["note"] = (cur["note"] + " " + t).strip()[:400]

        elif section == "cardio":
            m = re.match(r"^([A-Z][a-z]{2}[^:]{0,30}):\s*(.+)$", t)
            if is_list and m and days_in(m.group(1)):
                spec, body = m.group(1), m.group(2).strip().rstrip(".")
                parts = re.split(r"\s+[—–]\s+", body, maxsplit=1)
                tail = re.match(r"^(.*?)\s*\(([^()]*)\)$", body)
                if len(parts) == 1 and tail:
                    parts = [tail.group(1), tail.group(2)]
                item = {"t": parts[0][:120], "d": (parts[1] if len(parts) > 1 else "")[:200]}
                if "optional" in spec.lower():
                    item["t"] = "Optional · " + item["t"]
                for d in days_in(spec):
                    cardio.setdefault(d, []).append(dict(item))
            elif t.lower().startswith("daily steps"):
                notes.append(t[:600])

        elif section == "mobility":
            m = re.match(r"^Daily[^(]*\(([^)]*)\)\s*:?$", t)
            if m and not is_list:
                routine_days = days_in(m.group(1))
                continue
            m = re.match(r"^(" + "|".join(WEEK) + r")\s+([^(:]+?)\s*\((\d+\s*min)\)\s*:\s*(.+)$", t)
            if m and not is_list:
                kind = m.group(2).strip().lower()
                title = ("Full mobility session" if "full" in kind else "Recovery stretch" if "recover" in kind else m.group(2).strip().capitalize())
                move.setdefault(m.group(1), []).append({"t": f"{title} · {m.group(3)}", "d": m.group(4).strip()[:300]})
                routine_days = None
                continue
            if is_list and routine_days:
                parts = re.split(r"\s+[—–]\s+", t, maxsplit=1)
                n, d = parts[0], (parts[1] if len(parts) > 1 else "")
                for day in routine_days:
                    move.setdefault(day, []).append({"t": n.strip()[:80], "d": d.strip()[:120]})

        elif section == "nutrition":
            low = t.lower()
            if not is_list:
                m = re.match(r"^([A-Z][A-Za-z\- ]{2,24})" + DASH + r"~?\s*([\d,]+)\s*cal(?:,\s*~?(\d+)\s*g\s*protein)?", t)
                if m:
                    meal = {"name": m.group(1).strip(), "desc": "", "cal": num(m.group(2)), "p": int(m.group(3) or 0) or "", "c": "", "f": ""}
                    nut["meals"].append(meal)
                    nsub = "meal"
                    continue
                meal = None
                nsub = ("macros" if low.startswith("daily macros") else "variety" if "variety" in low
                        else "notes" if low.startswith("notes") else "numbers" if low.startswith("your numbers") else "other")
                continue
            if nsub == "meal" and meal is not None:
                meal["desc"] = (meal["desc"] + " · " + t if meal["desc"] else t)[:300]
            elif nsub == "numbers" and low.startswith("daily target"):
                nut["targets"]["cal"] = num(t.split(":", 1)[1])
            elif nsub == "macros":
                m = re.match(r"^(Protein|Carbs?|Fat)s?\s*:\s*([\d,]+)\s*g", t, re.I)
                if m:
                    nut["targets"][m.group(1)[0].lower()] = num(m.group(2))
            elif nsub == "variety":
                nut["swaps"].append(t[:300])
            elif nsub == "notes":
                nut["notes"].append(t[:400])

    # Build the week: training days plus any day with cardio or mobility.
    out = []
    for d in WEEK:
        day = days.get(d)
        if day is None and (cardio.get(d) or move.get(d)):
            only_optional = all(x["t"].startswith("Optional") for x in cardio.get(d, []))
            day = {"weekday": d, "name": "Recovery day" if only_optional else "Cardio + mobility", "warmup": [], "warmup_label": "",
                   "cooldown": [], "cooldown_label": "", "note": "", "exercises": [], "condition": [], "move": []}
        if day is None:
            continue
        day["condition"] = cardio.get(d, [])
        day["move"] = move.get(d, [])
        out.append(day)

    meals = nut["meals"]
    nutrition = None
    if meals or nut["targets"]:
        nutrition = {"days": [{"meals": [dict(m) for m in meals]} for _ in range(7)], "targets": nut["targets"],
                     "notes": (nut["swaps"] + nut["notes"])[:20]}
    lifts = sum(1 for d in out if d["exercises"])
    return {
        "who": who[:120],
        "plan": {"days": out, "notes": notes[:10]},
        "nutrition": nutrition,
        "summary": f"{lifts} lifting days, {len(out) - lifts} cardio/recovery days, "
                   f"{sum(len(d['exercises']) for d in out)} exercises" + (f", {len(meals)} meals" if meals else ""),
    }


if __name__ == "__main__":
    import json
    import sys
    for f in sys.argv[1:]:
        r = parse_docx(open(f, "rb").read())
        print(json.dumps(r, indent=1, ensure_ascii=False))
