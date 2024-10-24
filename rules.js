// rules.js
const passwordRules = [
    {
        category: "Basic",
        rule: "Must contain at least 8 characters",
        validator: "password.length >= 8"
    },
    {
        category: "Math",
        rule: "Must contain the first 3 digits of π (3.14)",
        validator: "password.includes('314')"
    },
    {
        category: "Physics",
        rule: "Must contain E=mc² somewhere in the password",
        validator: "password.includes('E=mc2')"
    },
    {
        category: "Chemistry",
        rule: "Must contain the chemical symbol for Gold (Au)",
        validator: "password.includes('Au')"
    },
    {
        category: "Vocabulary",
        rule: "Must contain a word with more than 8 letters",
        validator: "password.match(/\\w{8,}/) !== null"
    },
    {
        category: "Math",
        rule: "Must contain a perfect square number greater than 50",
        validator: "/64|81|100|121|144|169|196|225/.test(password)"
    },
    {
        category: "Chess",
        rule: "Must contain a valid chess notation (e.g., Nf3, e4, Qd1)",
        validator: "/[KQRBN]?[a-h][1-8]/.test(password)"
    },
    {
        category: "Coding",
        rule: "Must contain a valid HTML tag",
        validator: "/<\\/?[a-z][a-z0-9]*>/i.test(password)"
    },
    {
        category: "Physics",
        rule: "Must contain the speed of light (3x10⁸)",
        validator: "password.includes('3x10⁸') || password.includes('3x108')"
    },
    {
        category: "Chemistry",
        rule: "Must contain pH followed by a number between 0-14",
        validator: "/pH[0-9]|pH1[0-4]/.test(password)"
    },
    {
        category: "Math",
        rule: "Must contain a prime number larger than 50",
        validator: "/53|59|61|67|71|73|79|83|89|97/.test(password)"
    },
    {
        category: "Vocabulary",
        rule: "Must contain a palindrome at least 3 letters long",
        validator: "password.match(/\\w*(\\w)\\w*\\1\\w*/) !== null"
    },
    {
        category: "Chess",
        rule: "Must contain the notation for castling (O-O or O-O-O)",
        validator: "/O-O-O|O-O/.test(password)"
    },
    {
        category: "Coding",
        rule: "Must contain a valid JavaScript variable name",
        validator: "/[a-zA-Z_$][a-zA-Z0-9_$]*/.test(password)"
    },
    {
        category: "Physics",
        rule: "Must contain the gravitational acceleration (9.81 m/s²)",
        validator: "password.includes('9.81')"
    },
    {
        category: "Chemistry",
        rule: "Must contain a noble gas symbol (He, Ne, Ar, Kr, Xe, Rn)",
        validator: "/He|Ne|Ar|Kr|Xe|Rn/.test(password)"
    },
    {
        category: "Math",
        rule: "Must contain the golden ratio (1.618)",
        validator: "password.includes('1.618')"
    },
    {
        category: "Vocabulary",
        rule: "Must contain an onomatopoeia (e.g., buzz, hiss, bang)",
        validator: "/buzz|hiss|bang|pop|boom|crash|splash|whoosh/.test(password)"
    },
    {
        category: "Coding",
        rule: "Must contain a comparison operator (==, !=, <=, >=, ===)",
        validator: "/==|!=|<=|>=|===/.test(password)"
    },
    {
        category: "Chess",
        rule: "Must contain a chess piece in text (king, queen, rook, bishop, knight, pawn)",
        validator: "/king|queen|rook|bishop|knight|pawn/i.test(password)"
    },
    {
        category: "Physics",
        rule: "Must contain Planck's constant (6.626x10⁻³⁴)",
        validator: "password.includes('6.626x10-34')"
    },
    {
        category: "Chemistry",
        rule: "Must contain a valid electron configuration (e.g., 1s², 2s², 2p⁶)",
        validator: "/[1-7][s|p|d|f][¹²³⁴⁵⁶]/.test(password)"
    },
    {
        category: "Math",
        rule: "Must contain the quadratic formula (-b±√(b²-4ac))/(2a)",
        validator: "password.includes('(-b±√(b²-4ac))/(2a)')"
    },
    {
        category: "Vocabulary",
        rule: "Must contain an oxymoron (e.g., deafening silence, living dead)",
        validator: "/deafening silence|living dead|pretty ugly|only choice|act natural|same difference/.test(password)"
    },
    {
        category: "Coding",
        rule: "Must contain a valid CSS color (red, #fff, rgb(), hsl())",
        validator: "/#[0-9A-Fa-f]{3,6}|rgb\\(|hsl\\(|red|blue|green|yellow|purple|cyan|white|black/.test(password)"
    },
    {
        category: "Physics",
        rule: "Must contain Avogadro's number (6.022x10²³)",
        validator: "password.includes('6.022x10²³') || password.includes('6.022x10^23')"
    },
    {
        category: "Chess",
        rule: "Must contain a checkmate pattern name (Scholar's mate, Fool's mate)",
        validator: "/Scholar's mate|Fool's mate|Smothered mate|Back-rank mate/.test(password)"
    },
    {
        category: "Chemistry",
        rule: "Must contain a polyatomic ion (NH₄⁺, OH⁻, SO₄²⁻)",
        validator: "/NH₄⁺|OH⁻|SO₄²⁻|CO₃²⁻|PO₄³⁻/.test(password)"
    },
    {
        category: "Math",
        rule: "Must contain Euler's number (e = 2.718)",
        validator: "password.includes('2.718')"
    },
    {
        category: "Math",
        rule: "Must contain Euler's number (e = 2.718)",
        validator: "password.includes('2.718')"
    },
    {
        category: "Vocabulary",
        rule: "Must contain an example of alliteration (e.g., 'Peter Piper picked')",
        validator: "/([a-zA-Z])\\w*\\s\\1\\w*\\s\\1\\w*/.test(password)"
    },
    {
        category: "Coding",
        rule: "Must contain a regular expression pattern (/pattern/)",
        validator: "/\\/[^/]+\\/[gimy]*/.test(password)"
    },
    {
        category: "Physics",
        rule: "Must contain Boltzmann's constant (1.380649x10⁻²³)",
        validator: "password.includes('1.380649x10⁻²³') || password.includes('1.380649x10^-23')"
    },
    {
        category: "Chemistry",
        rule: "Must contain a transition metal with its oxidation state (Fe²⁺, Cu²⁺)",
        validator: "/Fe[²³]⁺|Cu[²³]⁺|Zn[²³]⁺/.test(password)"
    },
    {
        category: "Math",
        rule: "Must contain a complex number in the form a+bi",
        validator: "/-?\\d+\\+?-?\\d*i/.test(password)"
    },
    {
        category: "Chess",
        rule: "Must contain a famous chess opening (Sicilian, Ruy Lopez)",
        validator: "/Sicilian|Ruy Lopez|French Defense|Italian Game|Caro-Kann/.test(password)"
    },
    {
        category: "Coding",
        rule: "Must contain a SQL keyword (SELECT, FROM, WHERE)",
        validator: "/SELECT|FROM|WHERE|JOIN|GROUP BY|ORDER BY/i.test(password)"
    },
    {
        category: "Physics",
        rule: "Must contain one of Maxwell's equations (∇⋅E = ρ/ε₀)",
        validator: "password.includes('∇⋅E = ρ/ε₀') || password.includes('∇⋅B = 0')"
    },
    {
        category: "Vocabulary",
        rule: "Must contain a figure of speech (metaphor, simile with 'like' or 'as')",
        validator: "/\\w+ (like|as) \\w+/.test(password)"
    },
    {
        category: "Math",
        rule: "Must contain a trigonometric expression (sin, cos, tan)",
        validator: "/sin|cos|tan/.test(password)"
    },
    {
        category: "Chemistry",
        rule: "Must contain an organic functional group (alcohol -OH, aldehyde -CHO)",
        validator: "/-OH|-CHO|-COOH|-NH2/.test(password)"
    },
    {
        category: "Coding",
        rule: "Must contain a valid file extension (.js, .py, .html, .css)",
        validator: "/\\.js|\\.py|\\.html|\\.css|\\.java/.test(password)"
    },
    {
        category: "Physics",
        rule: "Must contain the Schrödinger equation (iħ∂ψ/∂t = Ĥψ)",
        validator: "password.includes('iħ∂ψ/∂t = Ĥψ')"
    },
    {
        category: "Chess",
        rule: "Must contain a chess endgame position (K+R vs K)",
        validator: "/K\\+R vs K|K\\+Q vs K|K\\+P vs K/.test(password)"
    },
    {
        category: "Math",
        rule: "Must contain a factorial expression (n!)",
        validator: "/\\d+!/.test(password)"
    },
    {
        category: "Vocabulary",
        rule: "Must contain a portmanteau word (brunch, smog, motel)",
        validator: "/brunch|smog|motel|spork|hangry|blog/.test(password)"
    },
    {
        category: "Chemistry",
        rule: "Must contain a buffer solution (HCO₃⁻/H₂CO₃)",
        validator: "password.includes('HCO₃⁻/H₂CO₃') || password.includes('CH₃COOH/CH₃COO⁻')"
    },
    {
        category: "Coding",
        rule: "Must contain a programming paradigm (OOP, functional, procedural)",
        validator: "/OOP|functional|procedural|imperative|declarative/.test(password)"
    },
    {
        category: "Physics",
        rule: "Must contain the uncertainty principle (Δx·Δp ≥ ħ/2)",
        validator: "password.includes('Δx·Δp ≥ ħ/2')"
    },
    {
        category: "Math",
        rule: "Must contain a series notation (Σ or Π)",
        validator: "/[ΣΠ]/.test(password)"
    },
    {
        category: "Chess",
        rule: "Must contain a chess tournament time control (40/2, G/60)",
        validator: "/\\d+\\/\\d+|G\\/\\d+/.test(password)"
    },
    {
        category: "Vocabulary",
        rule: "Must contain a malapropism (for all intensive purposes)",
        validator: "/intensive purposes|statue of limitations|mute point/.test(password)"
    },
    {
        category: "Coding",
        rule: "Must contain a design pattern name (Singleton, Observer, Factory)",
        validator: "/Singleton|Observer|Factory|Adapter|Decorator/.test(password)"
    },
    {
        category: "Chemistry",
        rule: "Must contain a spectroscopic technique (NMR, IR, UV-Vis)",
        validator: "/NMR|IR|UV-Vis|MS|XRD/.test(password)"
    },
    {
        category: "Physics",
        rule: "Must contain a fundamental force (gravity, electromagnetic, strong, weak)",
        validator: "/gravity|electromagnetic|strong force|weak force/.test(password)"
    },
    {
        category: "Math",
        rule: "Must contain a famous mathematical conjecture (Riemann, Goldbach)",
        validator: "/Riemann|Goldbach|Collatz|Twin Prime/.test(password)"
    }
];