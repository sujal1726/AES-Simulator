
let currentStep = 0;

const stepNames = [
    "SubBytes",
    "ShiftRows",
    "MixColumns",
    "AddRoundKey"
];

const stepDescriptions = [
    "Each byte is substituted using a predefined S-Box.",
    "Rows of the AES state matrix are shifted by different positions.",
    "Columns are mixed using mathematical operations in GF(2^8).",
    "The state is combined with a round key using XOR."
];

// Convert bytes into Base64
function toBase64(bytes) {
    let binary = "";

    for (let byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}

// Convert Base64 into bytes
function fromBase64(text) {
    const binary = atob(text.trim());

    return Uint8Array.from(binary,
        char => char.charCodeAt(0));
}

// Get selected AES key size
function getKeySize() {
    return Number(document.getElementById("aesType").value);
}

// Generate AES Key
async function generateKey() {
    try {
        const size = getKeySize();

        const key = await crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: size
            },
            true,
            ["encrypt", "decrypt"]
        );

        const rawKey = await crypto.subtle.exportKey("raw", key);

        document.getElementById("key").value =
            toBase64(new Uint8Array(rawKey));

        showMessage("AES key generated successfully!");

    } catch (error) {
        showMessage("Key generation failed: " + error.message);
    }
}

// Import user key
async function getImportedKey() {
    const keyText = document.getElementById("key").value;

    if (!keyText.trim()) {
        throw new Error("Please generate or enter an AES key.");
    }

    const rawKey = fromBase64(keyText);

    const expectedLength = getKeySize() / 8;

    if (rawKey.length !== expectedLength) {
        throw new Error("Invalid key length. Select the correct AES size.");
    }

    return await crypto.subtle.importKey(
        "raw",
        rawKey,
        {
            name: "AES-GCM"
        },
        false,
        ["encrypt", "decrypt"]
    );
}

// Encrypt Message
async function encryptText() {
    try {
        const plainText =
            document.getElementById("plainText").value;

        if (!plainText) {
            throw new Error("Please enter a message.");
        }

        const key = await getImportedKey();

        // Generate a random 12-byte IV
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const encodedText =
            new TextEncoder().encode(plainText);

        const encrypted = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            encodedText
        );

        // Store IV + Cipher Text together
        const cipherBytes = new Uint8Array(encrypted);

        const combined = new Uint8Array(
            iv.length + cipherBytes.length
        );

        combined.set(iv, 0);
        combined.set(cipherBytes, iv.length);

        const result = toBase64(combined);

        document.getElementById("cipherText").value = result;

        // Also prepare decryption input
        document.getElementById("decryptInput").value = result;

        showMessage("Message encrypted successfully!");

    } catch (error) {
        showMessage("Encryption failed: " + error.message);
    }
}

// Decrypt Message
async function decryptText() {
    try {
        const cipherText =
            document.getElementById("decryptInput").value;

        if (!cipherText.trim()) {
            throw new Error("Please enter cipher text.");
        }

        const key = await getImportedKey();

        const combined = fromBase64(cipherText);

        // First 12 bytes contain IV
        if (combined.length < 29) {
            throw new Error("Invalid encrypted data.");
        }

        const iv = combined.slice(0, 12);

        const encryptedData = combined.slice(12);

        const decrypted = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            encryptedData
        );

        const originalText =
            new TextDecoder().decode(decrypted);

        document.getElementById("decryptedText").value =
            originalText;

        showMessage("Message decrypted successfully!");

    } catch (error) {
        showMessage("Decryption failed. Check your key or cipher text.");
    }
}

// Copy Text
async function copyText(id) {
    try {
        const text = document.getElementById(id).value;

        if (!text) {
            throw new Error("Nothing to copy.");
        }

        await navigator.clipboard.writeText(text);

        showMessage("Copied successfully!");

    } catch (error) {
        showMessage("Copy failed. Select and copy manually.");
    }
}

// Move to next AES step
function nextStep() {
    currentStep++;

    if (currentStep >= 4) {
        currentStep = 0;
    }

    updateSteps();
}

// Update AES visualization
function updateSteps() {
    for (let i = 0; i < 4; i++) {
        const step = document.getElementById("step" + (i + 1));

        step.classList.toggle("active", i === currentStep);
    }

    document.getElementById("stepInfo").innerText =
        "Step " + (currentStep + 1) + ": " +
        stepNames[currentStep] + " - " +
        stepDescriptions[currentStep];
}

// Restart visualization
function resetSteps() {
    currentStep = 0;
    updateSteps();
}

// Show status message
function showMessage(text) {
    document.getElementById("message").innerText = text;
}

// Reset Everything
function resetAll() {
    document.getElementById("key").value = "";
    document.getElementById("plainText").value = "";
    document.getElementById("cipherText").value = "";
    document.getElementById("decryptInput").value = "";
    document.getElementById("decryptedText").value = "";

    document.getElementById("aesType").value = "128";

    resetSteps();

    showMessage("All fields have been reset.");
}
