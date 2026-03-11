import { useState, useEffect, useRef, useCallback } from "react";

// ─── CONSTANTS ────────────────────────────────────────────────────────────────
const COMMON_PASSWORDS = new Set([
  "password","123456","password1","12345678","qwerty","abc123","monkey","1234567",
  "letmein","trustno1","dragon","baseball","iloveyou","master","sunshine","ashley",
  "bailey","passw0rd","shadow","123123","654321","superman","qazwsx","michael",
  "football","password123","admin","welcome","login","hello","charlie","donald",
  "princess","solo","passw0rd","starwars","summer","jessica","password1","zxcvbn",
  "qwerty123","1q2w3e4r","111111","1234567890","00000000","987654321",
]);

const DICT_WORDS = [
  "the","be","to","of","and","a","in","that","have","it","for","not","on","with",
  "he","as","you","do","at","this","but","his","by","from","they","we","say","her",
  "she","or","an","will","my","one","all","would","there","their","what","so","up",
  "out","if","about","who","get","which","go","me","when","make","can","like","time",
  "no","just","him","know","take","people","into","year","your","good","some","could",
  "them","see","other","than","then","now","look","only","come","its","over","think",
  "also","back","after","use","two","how","our","work","first","well","way","even",
  "new","want","because","any","these","give","day","most","us","love","cat","dog",
  "house","car","blue","red","green","black","white","happy","cool","hot","sun","moon",
  "star","fire","ice","rock","water","wind","earth","sky","tree","flower","bird","fish",
];

const KEYBOARD_PATTERNS = [
  "qwerty","qwertyuiop","asdfgh","asdfghjkl","zxcvbn","zxcvbnm",
  "1234","12345","123456","1234567","12345678","123456789","1234567890",
  "0987654321","9876543210","abcdef","abcdefgh","zyxwvu",
  "qazwsx","qazwsxedc","!@#$%","!@#$%^","!@#$%^&",
];

// ─── CRACK TIME ENGINE ────────────────────────────────────────────────────────
function analyzePassword(pwd) {
  if (!pwd) return null;

  const len = pwd.length;
  const hasLower   = /[a-z]/.test(pwd);
  const hasUpper   = /[A-Z]/.test(pwd);
  const hasDigit   = /[0-9]/.test(pwd);
  const hasSymbol  = /[^a-zA-Z0-9]/.test(pwd);
  const hasSpace   = / /.test(pwd);

  // Charset size
  let charsetSize = 0;
  if (hasLower)  charsetSize += 26;
  if (hasUpper)  charsetSize += 26;
  if (hasDigit)  charsetSize += 10;
  if (hasSymbol) charsetSize += 32;
  if (hasSpace)  charsetSize += 1;
  charsetSize = Math.max(charsetSize, 1);

  // Base entropy
  let entropy = len * Math.log2(charsetSize);

  // Penalties
  const penalties = [];
  const bonuses   = [];

  // Common password
  if (COMMON_PASSWORDS.has(pwd.toLowerCase())) {
    entropy = Math.min(entropy, 8);
    penalties.push({ icon:"💀", text:"This is one of the most commonly used passwords — crackers check these first, instantly." });
  }

  // Dictionary word base
  const lw = pwd.toLowerCase();
  const matchedWord = DICT_WORDS.find(w => w.length > 3 && lw.includes(w));
  if (matchedWord && len < 16) {
    entropy *= 0.65;
    penalties.push({ icon:"📖", text:`Contains common word "${matchedWord}" — dictionary attacks target these directly.` });
  }

  // Keyboard pattern
  const kp = KEYBOARD_PATTERNS.find(p => lw.includes(p));
  if (kp) {
    entropy *= 0.55;
    penalties.push({ icon:"⌨️", text:`Contains keyboard pattern "${kp}" — these are in every cracker's ruleset.` });
  }

  // Leet substitution (p@ssw0rd type)
  const leetified = lw.replace(/@/g,"a").replace(/0/g,"o").replace(/1/g,"i").replace(/3/g,"e").replace(/\$/g,"s").replace(/5/g,"s");
  if (COMMON_PASSWORDS.has(leetified) && !COMMON_PASSWORDS.has(lw)) {
    entropy *= 0.5;
    penalties.push({ icon:"🔄", text:"Leet-speak substitutions (@ for a, 0 for o) are a known cracking technique — won't fool modern tools." });
  }

  // Repeated characters
  if (/(.)\1{2,}/.test(pwd)) {
    entropy *= 0.7;
    penalties.push({ icon:"🔁", text:"Repeated characters reduce entropy significantly — e.g. 'aaa' or '111'." });
  }

  // All same case + no symbols
  if (!hasUpper && !hasSymbol && !hasDigit) {
    entropy *= 0.8;
    penalties.push({ icon:"🔡", text:"Lowercase-only passwords have a much smaller search space — mix in uppercase and symbols." });
  }

  // Short
  if (len < 8) {
    entropy *= 0.5;
    penalties.push({ icon:"📏", text:`Only ${len} characters — short passwords are brute-forced in seconds even without tricks.` });
  }

  // Bonuses
  if (len >= 16) bonuses.push({ icon:"📏", text:`Long password (${len} chars) — length is the single most powerful factor in password strength.` });
  if (len >= 20) bonuses.push({ icon:"🚀", text:"20+ characters makes brute force practically impossible even with future hardware." });
  if (hasLower && hasUpper && hasDigit && hasSymbol)
    bonuses.push({ icon:"🎨", text:"Uses all four character types — maximizes the search space an attacker must cover." });
  if (hasSpace) bonuses.push({ icon:"🌌", text:"Contains spaces — uncommon and adds meaningful entropy." });

  // Passphrase detection
  const wordCount = pwd.trim().split(/\s+/).filter(w => w.length > 2).length;
  if (wordCount >= 3 && len >= 16) {
    entropy = Math.max(entropy, 55);
    bonuses.push({ icon:"💬", text:"Passphrase detected — multiple words create high entropy that's also memorable. Excellent strategy." });
  }

  entropy = Math.max(0, Math.min(entropy, 128));

  // Crack time calculation
  // Modern GPU cluster: ~100 billion hashes/sec (bcrypt slower, MD5 faster — we use MD5 scenario for dramatic effect)
  const GUESSES_PER_SEC = 1e10; // 10 billion/sec (modern GPU)
  const combinations = Math.pow(2, entropy);
  const secondsTocrack = combinations / GUESSES_PER_SEC / 2; // average half

  return {
    entropy: Math.round(entropy),
    charsetSize,
    secondsToCrack: secondsTocrack,
    penalties,
    bonuses,
    hasLower, hasUpper, hasDigit, hasSymbol,
    len,
  };
}

function formatCrackTime(seconds) {
  if (seconds < 0.001)   return { label: "Instantly",          color: "#ef4444", tier: 0 };
  if (seconds < 1)       return { label: "Less than a second", color: "#ef4444", tier: 0 };
  if (seconds < 60)      return { label: `${Math.round(seconds)} seconds`,    color: "#f97316", tier: 1 };
  if (seconds < 3600)    return { label: `${Math.round(seconds/60)} minutes`, color: "#f97316", tier: 1 };
  if (seconds < 86400)   return { label: `${Math.round(seconds/3600)} hours`, color: "#eab308", tier: 2 };
  if (seconds < 2592000) return { label: `${Math.round(seconds/86400)} days`, color: "#eab308", tier: 2 };
  if (seconds < 31536000)return { label: `${Math.round(seconds/2592000)} months`, color: "#84cc16", tier: 3 };
  if (seconds < 3153600000) return { label: `${Math.round(seconds/31536000)} years`, color: "#22c55e", tier: 4 };
  if (seconds < 3.15e13) return { label: `${Math.round(seconds/3153600000).toLocaleString()} centuries`, color: "#06b6d4", tier: 5 };
  return { label: "Longer than the age of the universe", color: "#8b5cf6", tier: 6 };
}

function strengthLabel(entropy) {
  if (entropy < 25) return { label:"Catastrophic",  short:"CRITICAL",  color:"#ef4444" };
  if (entropy < 35) return { label:"Very Weak",      short:"VERY WEAK", color:"#f97316" };
  if (entropy < 50) return { label:"Weak",           short:"WEAK",      color:"#eab308" };
  if (entropy < 65) return { label:"Fair",           short:"FAIR",      color:"#84cc16" };
  if (entropy < 80) return { label:"Strong",         short:"STRONG",    color:"#22c55e" };
  if (entropy < 100)return { label:"Very Strong",    short:"V.STRONG",  color:"#06b6d4" };
  return               { label:"Unbreakable",        short:"FORTRESS",  color:"#8b5cf6" };
}

// ─── CHALLENGES ───────────────────────────────────────────────────────────────
const CHALLENGES = [
  {
    id:1, title:"Escape the Basics",
    task:"Create a password with at least 12 characters using uppercase, lowercase, and numbers.",
    check: a => a && a.len>=12 && a.hasUpper && a.hasLower && a.hasDigit,
    hint:"Try something like 'Coffee2Morning42' — mix words with numbers.",
    xp:100,
  },
  {
    id:2, title:"Symbol Power",
    task:"Create a password with 14+ characters that includes at least one symbol (!@#$%^&*).",
    check: a => a && a.len>=14 && a.hasSymbol,
    hint:"Add a symbol somewhere meaningful: 'BlueSky#Morning2026'",
    xp:150,
  },
  {
    id:3, title:"Passphrase Builder",
    task:"Build a passphrase of 3+ words separated by spaces, totaling 20+ characters.",
    check: a => {
      if (!a || a.len < 20) return false;
      const words = a.len > 0 && arguments[0] ? arguments[0].trim().split(/\s+/).filter(w=>w.length>1) : [];
      return words.length >= 3;
    },
    checkRaw: (pwd, a) => {
      if (!a || a.len < 20) return false;
      const words = pwd.trim().split(/\s+/).filter(w=>w.length>1);
      return words.length >= 3;
    },
    hint:"Try three random words with spaces: 'purple elephant sings' — long and memorable!",
    xp:200,
  },
  {
    id:4, title:"Crack-Proof Fortress",
    task:"Create a password that would take more than 1,000 years to crack.",
    check: a => a && a.secondsToCrack > 31536000 * 1000,
    hint:"Combine length, symbols, mixed case, and avoid dictionary words.",
    xp:250,
  },
  {
    id:5, title:"Entropy Master",
    task:"Achieve 80+ bits of entropy without using a simple keyboard pattern.",
    check: a => a && a.entropy >= 80,
    hint:"A 16-character password with all character types gets you there easily.",
    xp:300,
  },
];

// Persistent score store (session)
let SCORE_STORE = [];
function saveScore(name, score, completed) {
  SCORE_STORE = [...SCORE_STORE, {
    name, score, completed,
    date: new Date().toLocaleDateString("en-PH",{month:"short",day:"numeric",year:"numeric"}),
  }].sort((a,b)=>b.score-a.score).slice(0,20);
}

// ─── COLORS ───────────────────────────────────────────────────────────────────
const C = {
  bg:"#fdf2f8", bgCard:"#ffffff", bgSoft:"#fce7f3", bgDeep:"#fdf4ff",
  border:"#fbcfe8", borderSoft:"#f9a8d4",
  pink:"#db2777", pinkL:"#f472b6", pinkXL:"#fce7f3",
  teal:"#0e7490", tealL:"#22d3ee",
  violet:"#7c3aed", violetL:"#c084fc",
  gold:"#d97706", goldL:"#fbbf24",
  green:"#059669", greenL:"#6ee7b7",
  red:"#dc2626", redL:"#fca5a5",
  text:"#1e1b2e", textMd:"#4a3f5c", textSm:"#9580a8",
};

// ─── MAIN ─────────────────────────────────────────────────────────────────────
export default function PasswordArena() {
  const [screen, setScreen]         = useState("home");
  const [playerName, setPlayerName] = useState("");
  const [nameInput, setNameInput]   = useState("");
  const [nameError, setNameError]   = useState("");

  const [password, setPassword]     = useState("");
  const [showPwd, setShowPwd]       = useState(false);
  const [analysis, setAnalysis]     = useState(null);
  const [crackTime, setCrackTime]   = useState(null);
  const [strength, setStrength]     = useState(null);

  const [score, setScore]           = useState(0);
  const [completedChallenges, setCompletedChallenges] = useState(new Set());
  const [newlyCompleted, setNewlyCompleted] = useState(null);
  const [currentChallenge, setCurrentChallenge] = useState(0);

  const [highScores, setHighScores] = useState([]);
  const [dots, setDots]             = useState([]);
  const [crackAnim, setCrackAnim]   = useState(false);
  const [tier, setTier]             = useState(0);
  const prevTierRef                 = useRef(0);

  useEffect(() => {
    setDots(Array.from({length:18},(_,i)=>({
      id:i, x:Math.random()*100, y:Math.random()*100,
      r:1.5+Math.random()*3, dur:5+Math.random()*7, del:Math.random()*4,
      c:i%3===0?C.pinkL:i%3===1?C.tealL:C.violetL,
    })));
  }, []);

  // Analyse on every keystroke
  useEffect(() => {
    if (!password) { setAnalysis(null); setCrackTime(null); setStrength(null); return; }
    const a = analyzePassword(password);
    const ct = formatCrackTime(a.secondsToCrack);
    const s  = strengthLabel(a.entropy);
    setAnalysis(a);
    setCrackTime(ct);
    setStrength(s);

    // Animate tier change
    if (ct.tier !== prevTierRef.current) {
      setCrackAnim(true);
      setTimeout(() => setCrackAnim(false), 600);
      prevTierRef.current = ct.tier;
    }

    // Check challenges
    const ch = CHALLENGES[currentChallenge];
    if (ch) {
      const pass = ch.checkRaw ? ch.checkRaw(password, a) : ch.check(a);
      if (pass && !completedChallenges.has(ch.id)) {
        const updated = new Set(completedChallenges);
        updated.add(ch.id);
        setCompletedChallenges(updated);
        setScore(prev => prev + ch.xp);
        setNewlyCompleted(ch);
        setTimeout(() => setNewlyCompleted(null), 3000);
        if (currentChallenge + 1 < CHALLENGES.length) {
          setTimeout(() => { setCurrentChallenge(p => p+1); setPassword(""); }, 1500);
        }
      }
    }
  }, [password]);

  function startGame() {
    if (!nameInput.trim()) { setNameError("Please enter your name to continue. 🌸"); return; }
    setPlayerName(nameInput.trim()); setNameError("");
    setScore(0); setCompletedChallenges(new Set());
    setCurrentChallenge(0); setPassword(""); setAnalysis(null);
    setScreen("game");
  }

  function finishGame() {
    saveScore(playerName, score, completedChallenges.size);
    setHighScores([...SCORE_STORE]);
    setScreen("final");
  }

  function openScores() { setHighScores([...SCORE_STORE]); setScreen("scores"); }

  // Progress bar color based on entropy
  const barColor = strength ? strength.color : C.border;
  const barWidth = analysis ? Math.min(100, (analysis.entropy / 128) * 100) : 0;

  const css = `
    @import url('https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800;900&family=Playfair+Display:wght@700;900&family=Share+Tech+Mono&display=swap');
    *{box-sizing:border-box;}
    body{margin:0;background:${C.bg};}
    .root{font-family:'Nunito',sans-serif;min-height:100vh;}
    @keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-12px)}}
    @keyframes fadeUp{from{transform:translateY(16px);opacity:0}to{transform:translateY(0);opacity:1}}
    @keyframes slideIn{from{transform:translateX(80px);opacity:0}to{transform:translateX(0);opacity:1}}
    @keyframes popIn{0%{transform:scale(.7);opacity:0}70%{transform:scale(1.1)}100%{transform:scale(1);opacity:1}}
    @keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-6px)}40%{transform:translateX(6px)}60%{transform:translateX(-4px)}80%{transform:translateX(4px)}}
    @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
    @keyframes shimmer{0%{background-position:-200% center}100%{background-position:200% center}}
    @keyframes barGrow{from{width:0}to{width:var(--w)}}
    @keyframes scanline{0%{top:-10%}100%{top:110%}}
    @keyframes glitch{0%,100%{clip-path:inset(0 0 100% 0)}10%{clip-path:inset(10% 0 50% 0)}20%{clip-path:inset(40% 0 20% 0)}30%{clip-path:inset(60% 0 10% 0)}50%{clip-path:inset(20% 0 60% 0)}70%{clip-path:inset(5% 0 80% 0)}90%{clip-path:inset(80% 0 5% 0)}}
    .shimmer{
      background:linear-gradient(90deg,${C.pink},${C.violet},${C.teal},${C.pink});
      background-size:200% auto;-webkit-background-clip:text;-webkit-text-fill-color:transparent;
      animation:shimmer 3s linear infinite;
    }
    .card{background:#fff;border:1.5px solid ${C.border};border-radius:20px;padding:22px;box-shadow:0 2px 20px rgba(219,39,119,.07);}
    .chip{background:#fff;border:1.5px solid ${C.border};border-radius:14px;padding:8px 16px;text-align:center;box-shadow:0 2px 10px rgba(219,39,119,.06);}
    .pill{display:flex;align-items:center;gap:8px;background:${C.bgSoft};border:1.5px solid ${C.border};border-radius:50px;padding:7px 14px;}
    .btn-main{background:linear-gradient(135deg,${C.pink},${C.violet});border:none;color:#fff;cursor:pointer;padding:14px 36px;border-radius:50px;font-family:'Nunito',sans-serif;font-size:15px;font-weight:800;letter-spacing:.5px;transition:all .25s;box-shadow:0 6px 22px rgba(219,39,119,.35);}
    .btn-main:hover{transform:translateY(-2px);box-shadow:0 10px 32px rgba(219,39,119,.5);}
    .btn-out{background:transparent;border:2px solid ${C.pink};color:${C.pink};cursor:pointer;padding:12px 28px;border-radius:50px;font-family:'Nunito',sans-serif;font-size:14px;font-weight:700;transition:all .2s;}
    .btn-out:hover{background:${C.pink};color:#fff;transform:translateY(-1px);}
    .btn-sm{background:linear-gradient(135deg,${C.teal},${C.violet});border:none;color:#fff;cursor:pointer;padding:10px 22px;border-radius:50px;font-family:'Nunito',sans-serif;font-size:13px;font-weight:700;transition:all .2s;box-shadow:0 4px 14px rgba(14,116,144,.3);}
    .btn-sm:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(14,116,144,.45);}
    .inp{background:#fff;border:2px solid ${C.border};border-radius:14px;padding:13px 18px;font-family:'Nunito',sans-serif;font-size:15px;color:${C.text};width:100%;transition:border .2s;outline:none;}
    .inp:focus{border-color:${C.pink};box-shadow:0 0 0 3px rgba(219,39,119,.14);}
    .pwd-inp{background:${C.bgDeep};border:2px solid ${C.border};border-radius:16px;padding:16px 56px 16px 20px;font-family:'Share Tech Mono',monospace;font-size:18px;color:${C.text};width:100%;transition:all .25s;outline:none;letter-spacing:2px;}
    .pwd-inp:focus{border-color:${C.pink};box-shadow:0 0 0 4px rgba(219,39,119,.14);background:#fff;}
    .score-row{display:flex;align-items:center;gap:12px;border-radius:12px;padding:10px 14px;transition:background .15s;}
    .score-row:nth-child(odd){background:${C.bgSoft};}
    .score-row:hover{background:${C.pinkXL};}
    .crack-display{transition:all .4s ease;}
    .crack-display.anim{animation:popIn .5s ease;}
    .challenge-card{background:#fff;border:1.5px solid ${C.border};border-radius:16px;padding:18px 20px;transition:all .3s;}
    .challenge-card.done{background:linear-gradient(135deg,#f0fdf4,#dcfce7);border-color:#86efac;}
    .challenge-card.active{border-color:${C.pink};box-shadow:0 0 0 3px rgba(219,39,119,.12);}
    .req-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;transition:all .3s;}
    .req-dot.met{background:${C.green};}
    .req-dot.unmet{background:${C.border};}
  `;

  // ─── RENDER ─────────────────────────────────────────────────────────────────
  return (
    <div className="root" style={{background:C.bg,color:C.text,position:"relative",overflow:"hidden"}}>
      <style>{css}</style>

      {/* BG particles */}
      <div style={{position:"fixed",inset:0,zIndex:0,pointerEvents:"none",overflow:"hidden"}}>
        <div style={{position:"absolute",top:-140,right:-140,width:450,height:450,borderRadius:"50%",background:`radial-gradient(circle,${C.pinkL}1e,transparent 70%)`}}/>
        <div style={{position:"absolute",bottom:-100,left:-100,width:400,height:400,borderRadius:"50%",background:`radial-gradient(circle,${C.tealL}18,transparent 70%)`}}/>
        <div style={{position:"absolute",top:"40%",left:"42%",width:300,height:300,borderRadius:"50%",background:`radial-gradient(circle,${C.violetL}14,transparent 70%)`}}/>
        {dots.map(d=>(
          <div key={d.id} style={{position:"absolute",left:`${d.x}%`,top:`${d.y}%`,width:d.r*2,height:d.r*2,borderRadius:"50%",background:d.c,opacity:.28,animation:`float ${d.dur}s ease-in-out ${d.del}s infinite`}}/>
        ))}
      </div>

      {/* Challenge complete toast */}
      {newlyCompleted && (
        <div style={{position:"fixed",top:20,right:20,zIndex:300,background:"#fff",border:`2px solid ${C.goldL}`,borderRadius:18,padding:"14px 20px",boxShadow:`0 8px 36px rgba(217,119,6,.28)`,animation:"slideIn .4s ease",maxWidth:280}}>
          <div style={{fontSize:10,fontWeight:800,color:C.gold,letterSpacing:2,marginBottom:4}}>✅ CHALLENGE COMPLETE</div>
          <div style={{fontSize:17,fontWeight:900}}>{newlyCompleted.title}</div>
          <div style={{fontSize:13,color:C.textSm,marginTop:3}}>+{newlyCompleted.xp} XP earned!</div>
        </div>
      )}

      {/* ── HOME ── */}
      {screen==="home" && (
        <div style={{position:"relative",zIndex:1,maxWidth:780,margin:"0 auto",padding:"40px 20px 70px"}}>
          <div style={{display:"flex",justifyContent:"center",marginBottom:28}}>
            <div style={{display:"inline-flex",alignItems:"center",gap:10,background:"#fff",border:`1.5px solid ${C.border}`,borderRadius:50,padding:"8px 22px",boxShadow:`0 2px 14px rgba(219,39,119,.1)`}}>
              <span style={{fontSize:18}}>💜</span>
              <span style={{fontSize:12,fontWeight:800,color:C.textMd}}>Girls in ICT Day · ITU</span>
              <span style={{width:1,height:16,background:C.border,display:"inline-block"}}/>
              <span style={{fontSize:12,fontWeight:800,color:C.teal}}>DICT Region IV-A</span>
            </div>
          </div>

          <div style={{textAlign:"center",marginBottom:32}}>
            <div style={{fontSize:12,fontWeight:700,letterSpacing:4,color:C.textSm,marginBottom:10,textTransform:"uppercase"}}>Module 2</div>
            <h1 style={{fontFamily:"'Playfair Display',serif",fontSize:"clamp(38px,7vw,66px)",fontWeight:900,margin:"0 0 10px",lineHeight:1.05}}>
              <span className="shimmer">Password Arena</span>
            </h1>
            <div style={{fontSize:13,fontWeight:700,letterSpacing:3,color:C.textSm,textTransform:"uppercase",marginBottom:18}}>
              Strength Simulator & Crack-Time Visualizer
            </div>
            <p style={{color:C.textMd,maxWidth:540,margin:"0 auto",lineHeight:1.8,fontSize:15}}>
              Type any password and watch in real time how long it would take a modern hacker to crack it.
              Complete challenges to earn XP and learn what makes passwords truly secure. 🔐
            </p>
          </div>

          {/* Name entry */}
          <div className="card" style={{maxWidth:460,margin:"0 auto 32px",textAlign:"center"}}>
            <div style={{fontSize:13,fontWeight:800,color:C.pink,letterSpacing:1,marginBottom:14}}>✨ ENTER YOUR NAME TO BEGIN</div>
            <input className="inp" placeholder="Your name or username…" value={nameInput}
              onChange={e=>{setNameInput(e.target.value);setNameError("");}}
              onKeyDown={e=>e.key==="Enter"&&startGame()} maxLength={30}/>
            {nameError && <div style={{fontSize:12,color:C.red,marginTop:8,fontWeight:600}}>{nameError}</div>}
            <div style={{display:"flex",gap:10,justifyContent:"center",marginTop:18,flexWrap:"wrap"}}>
              <button className="btn-main" onClick={startGame}>▶ Start Arena</button>
              <button className="btn-out" onClick={openScores}>🏆 High Scores</button>
            </div>
          </div>

          {/* What you'll learn */}
          <div className="card" style={{marginBottom:20}}>
            <div style={{fontSize:11,fontWeight:800,letterSpacing:2,color:C.textSm,marginBottom:16}}>WHAT YOU'LL LEARN</div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(200px,1fr))",gap:14}}>
              {[
                {icon:"⏱️",t:"How long passwords take to crack",d:"See real crack times — from milliseconds to centuries"},
                {icon:"🧮",t:"What entropy means",d:"Understand the math behind password strength"},
                {icon:"⚠️",t:"Why common tricks don't work",d:"P@ssw0rd isn't clever — learn why"},
                {icon:"🛡️",t:"How to build strong passwords",d:"Passphrases, length, and character diversity"},
              ].map((item,i)=>(
                <div key={i} style={{display:"flex",gap:12,alignItems:"flex-start"}}>
                  <span style={{fontSize:24,flexShrink:0}}>{item.icon}</span>
                  <div>
                    <div style={{fontSize:13,fontWeight:800,color:C.text,marginBottom:2}}>{item.t}</div>
                    <div style={{fontSize:11,color:C.textSm,lineHeight:1.5}}>{item.d}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Challenges preview */}
          <div className="card">
            <div style={{fontSize:11,fontWeight:800,letterSpacing:2,color:C.textSm,marginBottom:14}}>
              {CHALLENGES.length} CHALLENGES · {CHALLENGES.reduce((a,c)=>a+c.xp,0)} TOTAL XP
            </div>
            <div style={{display:"flex",flexDirection:"column",gap:8}}>
              {CHALLENGES.map((ch,i)=>(
                <div key={i} style={{display:"flex",alignItems:"center",gap:12,padding:"10px 14px",background:C.bgSoft,borderRadius:12}}>
                  <div style={{width:28,height:28,borderRadius:"50%",background:`linear-gradient(135deg,${C.pink},${C.violet})`,color:"#fff",display:"flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:900,flexShrink:0}}>{i+1}</div>
                  <div style={{flex:1}}>
                    <div style={{fontSize:13,fontWeight:800,color:C.text}}>{ch.title}</div>
                    <div style={{fontSize:11,color:C.textSm}}>{ch.task}</div>
                  </div>
                  <div style={{fontSize:12,fontWeight:700,color:C.gold}}>+{ch.xp} XP</div>
                </div>
              ))}
            </div>
          </div>

          <div style={{textAlign:"center",marginTop:36,fontSize:12,color:C.textSm,lineHeight:2}}>
            <strong style={{color:C.pink}}>Girls in ICT Day</strong> · Facilitated by <strong style={{color:C.teal}}>DICT Region IV-A</strong> · In partnership with <strong style={{color:C.violet}}>ITU</strong>
          </div>
        </div>
      )}

      {/* ── HIGH SCORES ── */}
      {screen==="scores" && (
        <div style={{position:"relative",zIndex:1,maxWidth:580,margin:"0 auto",padding:"50px 20px 70px"}}>
          <div style={{textAlign:"center",marginBottom:32}}>
            <div style={{fontSize:52,marginBottom:12,animation:"popIn .4s ease"}}>🏆</div>
            <h2 style={{fontFamily:"'Playfair Display',serif",fontSize:34,margin:"0 0 8px",color:C.text}}>Hall of Fame</h2>
            <div style={{fontSize:13,color:C.textSm}}>Password Arena · Top Challengers</div>
          </div>
          <div className="card" style={{marginBottom:24}}>
            {SCORE_STORE.length===0 ? (
              <div style={{textAlign:"center",padding:"36px 0",color:C.textSm}}>
                <div style={{fontSize:40,marginBottom:12}}>🎮</div>No scores yet — be the first!
              </div>
            ) : SCORE_STORE.map((s,i)=>(
              <div key={i} className="score-row">
                <div style={{width:34,height:34,borderRadius:"50%",display:"flex",alignItems:"center",justifyContent:"center",fontWeight:900,fontSize:14,flexShrink:0,
                  background:i===0?`linear-gradient(135deg,#f59e0b,#d97706)`:i===1?`linear-gradient(135deg,#9ca3af,#6b7280)`:i===2?`linear-gradient(135deg,#b45309,#92400e)`:C.bgSoft,
                  color:i<3?"#fff":C.textSm}}>
                  {i===0?"🥇":i===1?"🥈":i===2?"🥉":i+1}
                </div>
                <div style={{flex:1}}>
                  <div style={{fontWeight:800,fontSize:14,color:C.text}}>{s.name}</div>
                  <div style={{fontSize:11,color:C.textSm}}>{s.date} · {s.completed}/{CHALLENGES.length} challenges</div>
                </div>
                <div style={{fontWeight:900,fontSize:20,color:C.pink}}>{s.score.toLocaleString()} XP</div>
              </div>
            ))}
          </div>
          <div style={{textAlign:"center"}}>
            <button className="btn-main" onClick={()=>setScreen("home")}>← Back to Home</button>
          </div>
        </div>
      )}

      {/* ── GAME ── */}
      {screen==="game" && (
        <div style={{position:"relative",zIndex:1,maxWidth:900,margin:"0 auto",padding:"20px 16px 60px"}}>
          {/* HUD */}
          <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:18,flexWrap:"wrap"}}>
            <div style={{display:"flex",alignItems:"center",gap:8,background:"#fff",border:`1.5px solid ${C.border}`,borderRadius:50,padding:"6px 16px",boxShadow:`0 2px 10px rgba(219,39,119,.06)`}}>
              <span style={{fontSize:14}}>💜</span>
              <span style={{fontSize:12,fontWeight:800,color:C.textMd}}>Girls in ICT Day</span>
            </div>
            <div className="chip">
              <div style={{fontSize:10,fontWeight:700,color:C.textSm,letterSpacing:2}}>PLAYER</div>
              <div style={{fontSize:13,fontWeight:900,color:C.pink}}>{playerName}</div>
            </div>
            <div className="chip">
              <div style={{fontSize:10,fontWeight:700,color:C.textSm,letterSpacing:2}}>XP</div>
              <div style={{fontSize:13,fontWeight:900,color:C.gold}}>{score}</div>
            </div>
            <div className="chip">
              <div style={{fontSize:10,fontWeight:700,color:C.textSm,letterSpacing:2}}>DONE</div>
              <div style={{fontSize:13,fontWeight:900,color:C.violet}}>{completedChallenges.size}/{CHALLENGES.length}</div>
            </div>
            <div style={{flex:1,textAlign:"right"}}>
              <button className="btn-sm" onClick={finishGame}>Finish & See Results →</button>
            </div>
          </div>

          <div style={{display:"grid",gridTemplateColumns:"1fr 340px",gap:18,alignItems:"start"}}>
            {/* LEFT: Password input + analysis */}
            <div style={{display:"flex",flexDirection:"column",gap:16}}>

              {/* Password input */}
              <div className="card">
                <div style={{fontSize:11,fontWeight:800,letterSpacing:2,color:C.textSm,marginBottom:12}}>🔑 TYPE YOUR PASSWORD</div>
                <div style={{position:"relative"}}>
                  <input
                    className="pwd-inp"
                    type={showPwd?"text":"password"}
                    placeholder="Start typing…"
                    value={password}
                    onChange={e=>setPassword(e.target.value)}
                    autoComplete="off"
                    autoFocus
                  />
                  <button onClick={()=>setShowPwd(p=>!p)} style={{position:"absolute",right:16,top:"50%",transform:"translateY(-50%)",background:"none",border:"none",cursor:"pointer",fontSize:18,color:C.textSm,padding:4}}>
                    {showPwd?"🙈":"👁️"}
                  </button>
                </div>
                {password && (
                  <div style={{marginTop:14}}>
                    {/* Strength bar */}
                    <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:6}}>
                      <span style={{fontSize:11,fontWeight:700,color:C.textSm}}>STRENGTH</span>
                      <span style={{fontSize:12,fontWeight:900,color:strength?.color}}>{strength?.label}</span>
                    </div>
                    <div style={{height:8,background:C.bgSoft,borderRadius:8,overflow:"hidden",marginBottom:14}}>
                      <div style={{height:"100%",background:`linear-gradient(90deg,${barColor},${barColor}cc)`,borderRadius:8,width:`${barWidth}%`,transition:"width .4s ease, background .4s ease"}}/>
                    </div>

                    {/* Char type indicators */}
                    <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                      {[
                        {label:"Lowercase",met:analysis?.hasLower},
                        {label:"Uppercase",met:analysis?.hasUpper},
                        {label:"Numbers",met:analysis?.hasDigit},
                        {label:"Symbols",met:analysis?.hasSymbol},
                      ].map((r,i)=>(
                        <div key={i} style={{display:"flex",alignItems:"center",gap:5,background:r.met?`${C.green}15`:C.bgSoft,border:`1px solid ${r.met?C.greenL:C.border}`,borderRadius:50,padding:"4px 10px",transition:"all .3s"}}>
                          <div className={`req-dot ${r.met?"met":"unmet"}`}/>
                          <span style={{fontSize:11,fontWeight:700,color:r.met?C.green:C.textSm}}>{r.label}</span>
                        </div>
                      ))}
                      <div style={{display:"flex",alignItems:"center",gap:5,background:C.bgSoft,border:`1px solid ${C.border}`,borderRadius:50,padding:"4px 10px"}}>
                        <span style={{fontSize:11,fontWeight:700,color:C.textSm}}>{analysis?.len} chars</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Crack time display */}
              {analysis && crackTime && (
                <div style={{background:"#fff",border:`2px solid ${crackTime.color}44`,borderRadius:20,padding:"20px 22px",boxShadow:`0 4px 24px ${crackTime.color}18`,transition:"all .4s"}}>
                  <div style={{fontSize:11,fontWeight:800,letterSpacing:2,color:C.textSm,marginBottom:10}}>⚡ ESTIMATED CRACK TIME</div>
                  <div style={{fontSize:11,color:C.textSm,marginBottom:6}}>Using a modern GPU cluster (~10 billion guesses/sec)</div>

                  <div className={`crack-display${crackAnim?" anim":""}`} style={{
                    fontFamily:"'Share Tech Mono',monospace",
                    fontSize:"clamp(22px,4vw,36px)",
                    fontWeight:700,
                    color:crackTime.color,
                    marginBottom:12,
                    lineHeight:1.2,
                  }}>
                    {crackTime.label}
                  </div>

                  {/* Visual tier bar */}
                  <div style={{display:"flex",gap:4,marginBottom:16,alignItems:"center"}}>
                    {["Instant","Seconds","Hours","Months","Years","Centuries","Universe+"].map((t,i)=>(
                      <div key={i} style={{flex:1,height:6,borderRadius:3,background:i<=crackTime.tier?
                        ["#ef4444","#f97316","#eab308","#84cc16","#22c55e","#06b6d4","#8b5cf6"][i]
                        :C.bgSoft,transition:"background .4s ease"}}/>
                    ))}
                  </div>

                  {/* Entropy */}
                  <div style={{display:"flex",gap:16,flexWrap:"wrap"}}>
                    <div style={{background:C.bgSoft,borderRadius:10,padding:"8px 14px",textAlign:"center"}}>
                      <div style={{fontSize:20,fontWeight:900,color:C.violet}}>{analysis.entropy}</div>
                      <div style={{fontSize:10,fontWeight:700,color:C.textSm}}>BITS OF ENTROPY</div>
                    </div>
                    <div style={{background:C.bgSoft,borderRadius:10,padding:"8px 14px",textAlign:"center"}}>
                      <div style={{fontSize:20,fontWeight:900,color:C.teal}}>{analysis.charsetSize}</div>
                      <div style={{fontSize:10,fontWeight:700,color:C.textSm}}>CHARSET SIZE</div>
                    </div>
                    <div style={{flex:1,background:C.bgSoft,borderRadius:10,padding:"8px 14px"}}>
                      <div style={{fontSize:10,fontWeight:700,color:C.textSm,marginBottom:4}}>WHAT THIS MEANS</div>
                      <div style={{fontSize:11,color:C.textMd,lineHeight:1.5}}>
                        {analysis.entropy < 35
                          ? "Crackable in seconds by even basic tools. Do not use."
                          : analysis.entropy < 55
                          ? "A determined attacker could crack this in a reasonable time."
                          : analysis.entropy < 75
                          ? "Solid for most purposes. Could be improved with more length."
                          : analysis.entropy < 90
                          ? "Strong password. Safe against most real-world attacks."
                          : "Extremely strong. Only nation-state level resources could threaten this."}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Penalties & Bonuses */}
              {analysis && (analysis.penalties.length > 0 || analysis.bonuses.length > 0) && (
                <div className="card">
                  {analysis.penalties.length > 0 && (
                    <div style={{marginBottom:analysis.bonuses.length>0?16:0}}>
                      <div style={{fontSize:11,fontWeight:800,letterSpacing:2,color:C.red,marginBottom:10}}>🚩 WEAKNESSES DETECTED</div>
                      {analysis.penalties.map((p,i)=>(
                        <div key={i} style={{display:"flex",gap:10,marginBottom:8,fontSize:13,color:C.textMd,lineHeight:1.55,animation:"fadeUp .3s ease",animationDelay:`${i*.06}s`,animationFillMode:"both",opacity:0}}>
                          <span style={{flexShrink:0,fontSize:15}}>{p.icon}</span><span>{p.text}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {analysis.bonuses.length > 0 && (
                    <div>
                      <div style={{fontSize:11,fontWeight:800,letterSpacing:2,color:C.green,marginBottom:10}}>✅ STRENGTHS DETECTED</div>
                      {analysis.bonuses.map((b,i)=>(
                        <div key={i} style={{display:"flex",gap:10,marginBottom:8,fontSize:13,color:C.textMd,lineHeight:1.55,animation:"fadeUp .3s ease",animationDelay:`${i*.06}s`,animationFillMode:"both",opacity:0}}>
                          <span style={{flexShrink:0,fontSize:15}}>{b.icon}</span><span>{b.text}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Tip when empty */}
              {!password && (
                <div style={{background:"#fff",border:`1.5px dashed ${C.border}`,borderRadius:20,padding:"28px 24px",textAlign:"center",color:C.textSm}}>
                  <div style={{fontSize:36,marginBottom:10}}>⌨️</div>
                  <div style={{fontSize:14,fontWeight:700,marginBottom:6,color:C.textMd}}>Start typing to see your analysis</div>
                  <div style={{fontSize:13,lineHeight:1.6}}>Try common passwords, your name, or<br/>a passphrase — see what happens!</div>
                </div>
              )}
            </div>

            {/* RIGHT: Challenges */}
            <div style={{display:"flex",flexDirection:"column",gap:12}}>
              <div style={{fontSize:11,fontWeight:800,letterSpacing:2,color:C.textSm,marginBottom:2}}>🎯 CHALLENGES</div>

              {CHALLENGES.map((ch,i)=>{
                const done    = completedChallenges.has(ch.id);
                const active  = i === currentChallenge && !done;
                const locked  = i > currentChallenge && !done;
                return (
                  <div key={i} className={`challenge-card${done?" done":active?" active":""}`} style={{opacity:locked?.6:1}}>
                    <div style={{display:"flex",alignItems:"flex-start",gap:10}}>
                      <div style={{width:30,height:30,borderRadius:"50%",flexShrink:0,display:"flex",alignItems:"center",justifyContent:"center",fontSize:14,fontWeight:900,
                        background:done?`linear-gradient(135deg,${C.green},#047857)`:active?`linear-gradient(135deg,${C.pink},${C.violet})`:C.bgSoft,
                        color:done||active?"#fff":C.textSm}}>
                        {done?"✓":i+1}
                      </div>
                      <div style={{flex:1}}>
                        <div style={{fontSize:13,fontWeight:900,color:done?C.green:active?C.pink:C.textMd,marginBottom:4}}>{ch.title}</div>
                        <div style={{fontSize:11,color:C.textSm,lineHeight:1.5,marginBottom:active?8:0}}>{ch.task}</div>
                        {active && !done && (
                          <div style={{fontSize:11,color:C.teal,background:C.tealL+"15",border:`1px solid ${C.tealL}44`,borderRadius:8,padding:"6px 10px",lineHeight:1.5}}>
                            💡 {ch.hint}
                          </div>
                        )}
                      </div>
                      <div style={{fontSize:12,fontWeight:800,color:done?C.green:C.gold,flexShrink:0}}>+{ch.xp}</div>
                    </div>
                  </div>
                );
              })}

              {/* Progress */}
              <div className="card" style={{padding:"16px 18px"}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                  <span style={{fontSize:11,fontWeight:800,color:C.textSm,letterSpacing:1}}>PROGRESS</span>
                  <span style={{fontSize:12,fontWeight:900,color:C.pink}}>{completedChallenges.size}/{CHALLENGES.length}</span>
                </div>
                <div style={{height:6,background:C.bgSoft,borderRadius:6,overflow:"hidden"}}>
                  <div style={{height:"100%",background:`linear-gradient(90deg,${C.pink},${C.violet})`,borderRadius:6,width:`${(completedChallenges.size/CHALLENGES.length)*100}%`,transition:"width .5s ease"}}/>
                </div>
                <div style={{marginTop:10,fontSize:11,color:C.textSm}}>Total XP: <strong style={{color:C.gold}}>{score}</strong> / {CHALLENGES.reduce((a,c)=>a+c.xp,0)}</div>
              </div>

              {/* Quick tips */}
              <div className="card" style={{padding:"16px 18px"}}>
                <div style={{fontSize:11,fontWeight:800,color:C.textSm,letterSpacing:1,marginBottom:10}}>💡 QUICK TIPS</div>
                {[
                  "Length matters most — 16+ chars is ideal",
                  "3+ random words (passphrase) = strong & memorable",
                  "Avoid names, dates, dictionary words",
                  "P@ssw0rd tricks are well-known to crackers",
                  "Use a password manager for unique passwords",
                ].map((tip,i)=>(
                  <div key={i} style={{display:"flex",gap:8,marginBottom:7,fontSize:11,color:C.textMd,lineHeight:1.5}}>
                    <span style={{color:C.pink,fontWeight:900,flexShrink:0}}>›</span><span>{tip}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── FINAL ── */}
      {screen==="final" && (
        <div style={{position:"relative",zIndex:1,maxWidth:680,margin:"0 auto",padding:"50px 20px 80px"}}>
          <div style={{textAlign:"center",marginBottom:36}}>
            <div style={{fontSize:64,marginBottom:14,animation:"popIn .5s ease"}}>
              {completedChallenges.size === CHALLENGES.length ? "🏆" : completedChallenges.size >= 3 ? "🎯" : "📖"}
            </div>
            <div style={{fontSize:11,fontWeight:800,letterSpacing:3,color:C.gold,marginBottom:10}}>ARENA COMPLETE</div>
            <h2 style={{fontFamily:"'Playfair Display',serif",fontSize:34,margin:"0 0 8px",color:C.text}}>
              {completedChallenges.size === CHALLENGES.length ? `Fortress achieved, ${playerName}!` : `Well done, ${playerName}!`}
            </h2>
            <div style={{color:C.textSm}}>{completedChallenges.size} of {CHALLENGES.length} challenges completed</div>
          </div>

          {/* Stats */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:12,marginBottom:24}}>
            {[
              {label:"TOTAL XP",val:score,c:C.pink},
              {label:"CHALLENGES",val:`${completedChallenges.size}/${CHALLENGES.length}`,c:C.violet},
              {label:"MAX POSSIBLE",val:CHALLENGES.reduce((a,c)=>a+c.xp,0),c:C.gold},
            ].map((s,i)=>(
              <div key={i} className="chip" style={{padding:"18px 14px"}}>
                <div style={{fontSize:26,fontWeight:900,color:s.c}}>{s.val}</div>
                <div style={{fontSize:10,fontWeight:700,color:C.textSm,letterSpacing:1}}>{s.label}</div>
              </div>
            ))}
          </div>

          {/* Challenge results */}
          <div className="card" style={{marginBottom:24}}>
            <div style={{fontSize:11,fontWeight:800,letterSpacing:2,color:C.textSm,marginBottom:14}}>CHALLENGE RESULTS</div>
            {CHALLENGES.map((ch,i)=>(
              <div key={i} style={{display:"flex",alignItems:"center",gap:12,padding:"10px 0",borderBottom:i<CHALLENGES.length-1?`1px solid ${C.border}`:"none"}}>
                <span style={{fontSize:20}}>{completedChallenges.has(ch.id)?"✅":"❌"}</span>
                <div style={{flex:1}}>
                  <div style={{fontSize:13,fontWeight:800,color:C.text}}>{ch.title}</div>
                  <div style={{fontSize:11,color:C.textSm}}>{ch.task}</div>
                </div>
                <div style={{fontWeight:900,fontSize:14,color:completedChallenges.has(ch.id)?C.green:C.textSm}}>
                  {completedChallenges.has(ch.id)?`+${ch.xp} XP`:"—"}
                </div>
              </div>
            ))}
          </div>

          {/* Leaderboard */}
          <div className="card" style={{marginBottom:24}}>
            <div style={{fontSize:11,fontWeight:800,letterSpacing:2,color:C.textSm,marginBottom:14}}>🏆 LEADERBOARD</div>
            {SCORE_STORE.length===0 ? (
              <div style={{textAlign:"center",padding:"16px 0",color:C.textSm,fontSize:13}}>No other scores yet.</div>
            ) : SCORE_STORE.slice(0,10).map((s,i)=>(
              <div key={i} className="score-row" style={{background:s.name===playerName?C.pinkXL:i%2===0?C.bgSoft:"#fff"}}>
                <div style={{width:32,height:32,borderRadius:"50%",display:"flex",alignItems:"center",justifyContent:"center",fontWeight:900,fontSize:13,flexShrink:0,
                  background:i===0?`linear-gradient(135deg,#f59e0b,#d97706)`:i===1?`linear-gradient(135deg,#9ca3af,#6b7280)`:i===2?`linear-gradient(135deg,#b45309,#92400e)`:C.bgSoft,
                  color:i<3?"#fff":C.textSm}}>
                  {i===0?"🥇":i===1?"🥈":i===2?"🥉":i+1}
                </div>
                <div style={{flex:1}}>
                  <span style={{fontWeight:s.name===playerName?900:700,fontSize:14,color:s.name===playerName?C.pink:C.text}}>
                    {s.name}{s.name===playerName?" 👈":""}
                  </span>
                  <div style={{fontSize:11,color:C.textSm}}>{s.date} · {s.completed}/{CHALLENGES.length} challenges</div>
                </div>
                <div style={{fontWeight:900,fontSize:18,color:C.pink}}>{s.score} XP</div>
              </div>
            ))}
          </div>

          {/* Key takeaways */}
          <div className="card" style={{marginBottom:28}}>
            <div style={{fontSize:11,fontWeight:800,letterSpacing:2,color:C.teal,marginBottom:14}}>KEY TAKEAWAYS</div>
            {[
              "Length is the #1 factor — every extra character multiplies the search space exponentially",
              "Passphrases (3+ random words) are both strong AND memorable",
              "Common substitutions like @ for a or 0 for o are in every cracker's rulebook",
              "A password with 80+ bits of entropy is safe against any foreseeable hardware",
              "Use a password manager — you only need to remember one master passphrase",
              "Each account should have a unique password — reuse is a critical vulnerability",
            ].map((tip,i)=>(
              <div key={i} style={{display:"flex",gap:10,marginBottom:10,fontSize:13,color:C.textMd,lineHeight:1.55}}>
                <span style={{color:C.green,fontWeight:900,flexShrink:0}}>✓</span><span>{tip}</span>
              </div>
            ))}
          </div>

          <div style={{display:"flex",gap:12,justifyContent:"center",flexWrap:"wrap"}}>
            <button className="btn-main" onClick={()=>{setNameInput(playerName);setScreen("home");}}>↺ Play Again</button>
            <button className="btn-out" onClick={openScores}>🏆 Full Leaderboard</button>
          </div>

          <div style={{textAlign:"center",marginTop:36,fontSize:12,color:C.textSm,lineHeight:2}}>
            <strong style={{color:C.pink}}>Girls in ICT Day</strong> · Facilitated by <strong style={{color:C.teal}}>DICT Region IV-A</strong><br/>
            In partnership with <strong style={{color:C.violet}}>ITU</strong> · Empowering women and girls in technology 💜
          </div>
        </div>
      )}
    </div>
  );
}
