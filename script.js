/* =====================================
   RSA Secure Messaging
   Educational RSA Implementation
===================================== */


/* =====================================
   DOM ELEMENTS
===================================== */

const primePInput = document.getElementById("primeP");
const primeQInput = document.getElementById("primeQ");

const generateBtn = document.getElementById("generateBtn");

const publicKeyDisplay = document.getElementById("publicKey");
const privateKeyDisplay = document.getElementById("privateKey");

const keyError = document.getElementById("keyError");

const messageInput = document.getElementById("message");

const encryptBtn = document.getElementById("encryptBtn");
const decryptBtn = document.getElementById("decryptBtn");

const messageError = document.getElementById("messageError");

const resultDisplay = document.getElementById("result");

const calculationDisplay = document.getElementById("calculation");

const copyBtn = document.getElementById("copyBtn");

const operationLog = document.getElementById("operationLog");


/* =====================================
   RSA STATE
===================================== */

let rsa = {

    p: null,

    q: null,

    n: null,

    phi: null,

    e: null,

    d: null

};


/* =====================================
   UTILITY FUNCTIONS
===================================== */


/*
    Check whether a number is prime.
*/

function isPrime(number) {

    if (!Number.isInteger(number) || number < 2) {
        return false;
    }

    if (number === 2) {
        return true;
    }

    if (number % 2 === 0) {
        return false;
    }

    for (
        let i = 3;
        i * i <= number;
        i += 2
    ) {

        if (number % i === 0) {
            return false;
        }

    }

    return true;
}


/*
    Greatest Common Divisor
*/

function gcd(a, b) {

    a = Math.abs(a);
    b = Math.abs(b);

    while (b !== 0) {

        const temp = b;

        b = a % b;

        a = temp;

    }

    return a;
}


/*
    Extended Euclidean Algorithm
*/

function extendedGCD(a, b) {

    if (b === 0) {

        return {

            gcd: a,

            x: 1,

            y: 0

        };

    }

    const result = extendedGCD(b, a % b);

    return {

        gcd: result.gcd,

        x: result.y,

        y:
            result.x -
            Math.floor(a / b) * result.y

    };

}


/*
    Modular inverse

    Finds d such that:

        e × d ≡ 1 mod phi
*/

function modularInverse(e, phi) {

    const result = extendedGCD(e, phi);

    if (result.gcd !== 1) {

        return null;

    }

    return ((result.x % phi) + phi) % phi;

}


/*
    Fast modular exponentiation

    Calculates:

        base^exponent mod modulus
*/

function modularPower(base, exponent, modulus) {

    let result = 1n;

    let b = BigInt(base);

    let exp = BigInt(exponent);

    const mod = BigInt(modulus);


    b = b % mod;


    while (exp > 0n) {

        if (exp % 2n === 1n) {

            result =
                (result * b) % mod;

        }

        b =
            (b * b) % mod;

        exp =
            exp / 2n;

    }

    return result;

}


/*
    Clear message area
*/

function clearKeyError() {

    keyError.textContent = "";

    keyError.style.color = "";

}


function clearMessageError() {

    messageError.textContent = "";

    messageError.style.color = "";

}


/*
    Show error
*/

function showKeyError(message) {

    keyError.textContent = message;

    keyError.style.color = "#ff8f8f";

}


/*
    Show message error
*/

function showMessageError(message) {

    messageError.textContent = message;

    messageError.style.color = "#ff8f8f";

}


/*
    Show success
*/

function showMessageSuccess(message) {

    messageError.textContent = message;

    messageError.style.color = "#7ee787";

}


/* =====================================
   CHOOSE PUBLIC EXPONENT
===================================== */


/*
    Find a suitable e such that:

        1 < e < phi

        gcd(e, phi) = 1

    Common choices are tried first.
*/

function choosePublicExponent(phi) {

    const preferredValues = [

        65537,

        17,

        7,

        5,

        3

    ];


    for (const value of preferredValues) {

        if (
            value < phi &&
            gcd(value, phi) === 1
        ) {

            return value;

        }

    }


    for (
        let value = 3;
        value < phi;
        value++
    ) {

        if (gcd(value, phi) === 1) {

            return value;

        }

    }


    return null;

}


/* =====================================
   GENERATE RSA KEYS
===================================== */

function generateRSAKeys() {

    clearKeyError();

    clearMessageError();


    const p =
        Number(primePInput.value);

    const q =
        Number(primeQInput.value);


    /* Check p */

    if (!isPrime(p)) {

        showKeyError(
            "❌ p must be a valid prime number."
        );

        return;

    }


    /* Check q */

    if (!isPrime(q)) {

        showKeyError(
            "❌ q must be a valid prime number."
        );

        return;

    }


    /* p and q must be different */

    if (p === q) {

        showKeyError(
            "❌ p and q must be different prime numbers."
        );

        return;

    }


    /*
        Calculate n

        n = p × q
    */

    const n = p * q;


    /*
        Calculate phi

        φ(n) = (p-1)(q-1)
    */

    const phi =
        (p - 1) * (q - 1);


    /*
        Choose e
    */

    const e =
        choosePublicExponent(phi);


    if (e === null) {

        showKeyError(
            "❌ Could not find a suitable public exponent e."
        );

        return;

    }


    /*
        Calculate d

        d × e ≡ 1 mod phi
    */

    const d =
        modularInverse(e, phi);


    if (d === null) {

        showKeyError(
            "❌ Could not calculate the private key."
        );

        return;

    }


    /*
        Store RSA values
    */

    rsa.p = p;

    rsa.q = q;

    rsa.n = n;

    rsa.phi = phi;

    rsa.e = e;

    rsa.d = d;


    /*
        Display keys
    */

    publicKeyDisplay.textContent =
        `(${e}, ${n})`;

    privateKeyDisplay.textContent =
        `(${d}, ${n})`;


    /*
        Display calculations
    */

    calculationDisplay.textContent =

`RSA KEY GENERATION

Step 1: Select two prime numbers

p = ${p}
q = ${q}


Step 2: Calculate n

n = p × q
  = ${p} × ${q}
  = ${n}


Step 3: Calculate Euler's Totient

φ(n) = (p - 1)(q - 1)

φ(n) = (${p} - 1)(${q} - 1)
     = ${p - 1} × ${q - 1}
     = ${phi}


Step 4: Select public exponent e

e = ${e}

gcd(${e}, ${phi}) = ${gcd(e, phi)}

Since gcd(e, φ(n)) = 1,
e is valid.


Step 5: Calculate private exponent d

d × e ≡ 1 (mod φ(n))

${d} × ${e} ≡ 1 (mod ${phi})


Therefore:

Public Key  = (${e}, ${n})

Private Key = (${d}, ${n})`;


    /*
        Show success
    */

    showMessageSuccess(
        "✅ RSA keys generated successfully."
    );


    /*
        Add operation log
    */

    addLog(
        "Key Generation",
        `Public Key = (${e}, ${n}), Private Key = (${d}, ${n})`
    );

}


/* =====================================
   TEXT → NUMBER
===================================== */


/*
    Convert a character to a number.

    A = 1
    B = 2
    ...
    Z = 26

    Space = 0

    For simplicity this educational
    implementation supports letters
    and spaces.
*/

function characterToNumber(character) {

    const upper =
        character.toUpperCase();


    if (
        upper >= "A" &&
        upper <= "Z"
    ) {

        return (
            upper.charCodeAt(0) -
            64
        );

    }


    if (character === " ") {

        return 0;

    }


    return null;

}


/*
    Convert number back to character
*/

function numberToCharacter(number) {

    if (number === 0) {

        return " ";

    }


    if (
        number >= 1 &&
        number <= 26
    ) {

        return String.fromCharCode(
            64 + number
        );

    }


    return "?";

}


/* =====================================
   ENCRYPT MESSAGE
===================================== */

function encryptMessage() {

    clearMessageError();

    clearKeyError();


    /*
        Check whether keys exist
    */

    if (rsa.n === null) {

        showMessageError(
            "❌ Generate RSA keys first."
        );

        return;

    }


    const message =
        messageInput.value;


    if (message.length === 0) {

        showMessageError(
            "❌ Please enter a message."
        );

        return;

    }


    /*
        Check message characters
    */

    for (const character of message) {

        if (
            characterToNumber(character) === null
        ) {

            showMessageError(
                "❌ Please use only letters A-Z and spaces."
            );

            return;

        }

    }


    const encryptedValues = [];

    const calculationLines = [];


    calculationLines.push(
        "RSA ENCRYPTION"
    );

    calculationLines.push("");

    calculationLines.push(
        `Public Key = (${rsa.e}, ${rsa.n})`
    );

    calculationLines.push("");

    calculationLines.push(
        "Encryption Formula:"
    );

    calculationLines.push(
        "C = M^e mod n"
    );

    calculationLines.push("");


    /*
        Encrypt each character
    */

    for (const character of message) {

        const M =
            characterToNumber(character);


        const C =
            modularPower(
                M,
                rsa.e,
                rsa.n
            );


        encryptedValues.push(
            C.toString()
        );


        calculationLines.push(

            `${character === " "
                ? "SPACE"
                : character}
 → M = ${M}
 → C = ${M}^${rsa.e} mod ${rsa.n}
 → C = ${C}`

        );

    }


    /*
        Result is a space-separated
        list of ciphertext numbers.
    */

    const encryptedText =
        encryptedValues.join(" ");


    resultDisplay.textContent =
        encryptedText;


    calculationDisplay.textContent =
        calculationLines.join("\n");


    showMessageSuccess(
        "✅ Message encrypted successfully."
    );


    addLog(
        "Encryption",
        `Message encrypted: ${encryptedText}`
    );

}


/* =====================================
   DECRYPT MESSAGE
===================================== */

function decryptMessage() {

    clearMessageError();

    clearKeyError();


    /*
        Check keys
    */

    if (rsa.n === null) {

        showMessageError(
            "❌ Generate RSA keys first."
        );

        return;

    }


    const ciphertext =
        messageInput.value.trim();


    if (ciphertext.length === 0) {

        showMessageError(
            "❌ Enter ciphertext to decrypt."
        );

        return;

    }


    /*
        Ciphertext format:

        8 5 12 12 15
    */

    const values =
        ciphertext.split(/\s+/);


    const decryptedCharacters = [];

    const calculationLines = [];


    calculationLines.push(
        "RSA DECRYPTION"
    );

    calculationLines.push("");

    calculationLines.push(
        `Private Key = (${rsa.d}, ${rsa.n})`
    );

    calculationLines.push("");

    calculationLines.push(
        "Decryption Formula:"
    );

    calculationLines.push(
        "M = C^d mod n"
    );

    calculationLines.push("");


    /*
        Process every number
    */

    for (const value of values) {

        if (!/^\d+$/.test(value)) {

            showMessageError(
                "❌ Ciphertext must contain numbers separated by spaces."
            );

            return;

        }


        const C =
            BigInt(value);


        if (C >= BigInt(rsa.n)) {

            showMessageError(
                `❌ Ciphertext value ${value} must be smaller than n (${rsa.n}).`
            );

            return;

        }


        const M =
            modularPower(
                C,
                rsa.d,
                rsa.n
            );


        const numericMessage =
            Number(M);


        /*
            RSA educational mapping
            requires 0-26.
        */

        if (
            numericMessage < 0 ||
            numericMessage > 26
        ) {

            showMessageError(
                `❌ Decrypted value ${numericMessage} is outside the supported A-Z range.`
            );

            return;

        }


        const character =
            numberToCharacter(
                numericMessage
            );


        decryptedCharacters.push(
            character
        );


        calculationLines.push(

            `${C}
 → M = ${C}^${rsa.d} mod ${rsa.n}
 → M = ${numericMessage}
 → ${character === " "
                ? "SPACE"
                : character}`

        );

    }


    const decryptedText =
        decryptedCharacters.join("");


    resultDisplay.textContent =
        decryptedText;


    calculationDisplay.textContent =
        calculationLines.join("\n");


    showMessageSuccess(
        "✅ Message decrypted successfully."
    );


    addLog(
        "Decryption",
        `Message decrypted: ${decryptedText}`
    );

}


/* =====================================
   OPERATION LOG
===================================== */

function addLog(action, details) {

    /*
        Remove default message
    */

    if (
        operationLog.textContent.includes(
            "No operations performed yet."
        )
    ) {

        operationLog.innerHTML = "";

    }


    const entry =
        document.createElement("div");


    entry.className =
        "log-entry";


    const time =
        new Date().toLocaleTimeString();


    entry.innerHTML = `

        <div class="log-time">
            ${time}
        </div>

        <div class="log-action">
            ${action}
        </div>

        <div>
            ${details}
        </div>

    `;


    operationLog.prepend(entry);

}


/* =====================================
   COPY RESULT
===================================== */

async function copyResult() {

    const result =
        resultDisplay.textContent;


    if (
        !result ||
        result === "Your result will appear here..."
    ) {

        showMessageError(
            "❌ There is no result to copy."
        );

        return;

    }


    try {

        await navigator.clipboard.writeText(
            result
        );


        showMessageSuccess(
            "✅ Result copied to clipboard."
        );

    }

    catch (error) {

        showMessageError(
            "❌ Unable to copy the result."
        );

    }

}


/* =====================================
   CLEAR EVERYTHING
===================================== */

function clearAll() {

    primePInput.value = "";

    primeQInput.value = "";

    messageInput.value = "";


    publicKeyDisplay.textContent =
        "Not generated yet";


    privateKeyDisplay.textContent =
        "Not generated yet";


    resultDisplay.textContent =
        "Your result will appear here...";


    calculationDisplay.textContent =
        "RSA calculation details will appear here after an operation.";


    operationLog.innerHTML =
        "<p>No operations performed yet.</p>";


    clearKeyError();

    clearMessageError();


    rsa = {

        p: null,

        q: null,

        n: null,

        phi: null,

        e: null,

        d: null

    };

}


/* =====================================
   EVENT LISTENERS
===================================== */

generateBtn.addEventListener(
    "click",
    generateRSAKeys
);


encryptBtn.addEventListener(
    "click",
    encryptMessage
);


decryptBtn.addEventListener(
    "click",
    decryptMessage
);


copyBtn.addEventListener(
    "click",
    copyResult
);


/* =====================================
   INITIALIZATION
===================================== */

console.log(
    "RSA Secure Messaging loaded successfully."
);