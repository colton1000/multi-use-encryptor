/* ===================== Constants ===================== */

const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500MB limit
const MIN_PASSWORD_LENGTH = 4;
const ENC1_MAGIC = [69, 78, 67, 49]; // 'E','N','C','1'
const ENC1_MAGIC_STR = "ENC1";
const PBKDF2_ITERATIONS = 200000;
const PBKDF2_HASH = "SHA-256";

// Markers and patterns
const MARKERS = {
    ENC_BLOCK: "ENC_BLOCK:",
    ENCVAL: "ENCVAL:",
    EMBEDDED_START: "-----BEGIN ENCRYPTED BLOCK-----",
    EMBEDDED_END: "-----END ENCRYPTED BLOCK-----",
    PNG_STEGO: "PNG_STEGO_META:",
    LSB_STEGO: "LSBSTEGO1"
};

const REGEX_PATTERNS = {
    TEXT_NODES: /(>)([^<>]+?)(<)/g,
    NEWLINES: /\r?\n/
};

const MIME_TYPES = {
    TEXT: "text/plain",
    JSON: "application/json",
    XML: "application/xml",
    CSV: "text/csv",
    HTML: "text/html",
    PNG: "image/png",
    BINARY: "application/octet-stream"
};

const FILE_EXTENSIONS = {
    TXT: "txt",
    JSON: "json",
    CSV: "csv",
    XML: "xml",
    HTML: "html",
    HTM: "htm",
    PNG: "png",
    ENC: "enc"
};

const dropzone = document.getElementById("dropzone");
const algoSelect = document.getElementById("algoSelect");
const passwordInput = document.getElementById("password");
const output = document.getElementById("output");

let mode = "encrypt";

document.getElementById("encryptMode").onclick = () => switchMode("encrypt");
document.getElementById("decryptMode").onclick = () => switchMode("decrypt");

function switchMode(m) {
    mode = m;
    document.getElementById("encryptMode").classList.toggle("active", m === "encrypt");
    document.getElementById("decryptMode").classList.toggle("active", m === "decrypt");
    output.textContent = "";
}

/* ===================== Input Validation & Helpers ===================== */

function validateInput(password, arrayBuffer) {
    if (!password || password.length < MIN_PASSWORD_LENGTH) {
        throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
    }
    if (!arrayBuffer || arrayBuffer.byteLength === 0) {
        throw new Error("File is empty.");
    }
    if (arrayBuffer.byteLength > MAX_FILE_SIZE) {
        const sizeMB = (arrayBuffer.byteLength / (1024 * 1024)).toFixed(2);
        throw new Error(`File too large (${sizeMB}MB). Maximum: ${MAX_FILE_SIZE / (1024 * 1024)}MB.`);
    }
}

function transformFilename(name, pattern) {
    if (!name || typeof name !== "string") return "encrypted_file";
    return name.replace(/(\.[^.]*)?$/, pattern);
}

function safeBase64ToBuffer(b64Str) {
    try {
        return Uint8Array.from(atob(b64Str), c => c.charCodeAt(0)).buffer;
    } catch (err) {
        throw new Error("Invalid base64 data: " + err.message);
    }
}

dropzone.addEventListener("dragover", e => {
    e.preventDefault();
    dropzone.classList.add("dragover");
});

dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("dragover");
});

function download(blob, filename) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
}

/* ===================== Helpers & Binary Header ===================== */

const enc = new TextEncoder();
const dec = new TextDecoder();

async function deriveKey(password, salt, algoName) {
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: PBKDF2_ITERATIONS,
            hash: PBKDF2_HASH
        },
        keyMaterial,
        { name: algoName, length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

// Binary header format:
// [4 bytes magic 'E','N','C','1']
// [1 byte modeId]
// [16 bytes salt]
// [1 byte ivLen]
// [ivLen bytes iv]
// [ciphertext...]
function buildHeader(modeId, salt, iv, ciphertext) {
    const magic = new Uint8Array(ENC1_MAGIC);
    const ivLen = iv ? iv.length : 0;
    const header = new Uint8Array(4 + 1 + 16 + 1 + ivLen + ciphertext.byteLength);
    let offset = 0;
    header.set(magic, offset); offset += 4;
    header[offset++] = modeId;
    header.set(salt, offset); offset += 16;
    header[offset++] = ivLen;
    if (ivLen > 0) {
        header.set(iv, offset);
        offset += ivLen;
    }
    header.set(new Uint8Array(ciphertext), offset);
    return header.buffer;
}

function parseHeader(buffer) {
    const bytes = new Uint8Array(buffer);
    if (bytes.length < 4 + 1 + 16 + 1) throw new Error("Invalid header");
    const expectedMagic = ENC1_MAGIC;
    if (bytes[0] !== expectedMagic[0] || bytes[1] !== expectedMagic[1] || 
        bytes[2] !== expectedMagic[2] || bytes[3] !== expectedMagic[3]) {
        throw new Error("Not an ENC1 payload");
    }
    let offset = 4;
    const modeId = bytes[offset++];
    const salt = bytes.slice(offset, offset + 16); offset += 16;
    const ivLen = bytes[offset++];
    if (bytes.length < 4 + 1 + 16 + 1 + ivLen) throw new Error("Invalid header length");
    const iv = bytes.slice(offset, offset + ivLen); offset += ivLen;
    const ciphertext = bytes.slice(offset).buffer;
    return { modeId, salt, iv, ciphertext };
}

function getFileExtension(name) {
    if (!name || typeof name !== "string") return "";
    const idx = name.lastIndexOf(".");
    return idx === -1 ? "" : name.slice(idx + 1).toLowerCase();
}

/* ===================== Full-file encryption modes ===================== */

const MODE_FULL_AES_GCM = 1;
const MODE_FULL_AES_CBC = 2;
const MODE_FULL_AES_CTR = 3;
const MODE_FULL_XOR = 4;

async function encryptFullAESGCM(data, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt, "AES-GCM");
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
    return buildHeader(MODE_FULL_AES_GCM, salt, iv, ciphertext);
}

async function decryptFullAESGCM(buffer, password, salt, iv) {
    const key = await deriveKey(password, salt, "AES-GCM");
    return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, buffer);
}

async function encryptFullAESCBC(data, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(password, salt, "AES-CBC");
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, data);
    return buildHeader(MODE_FULL_AES_CBC, salt, iv, ciphertext);
}

async function decryptFullAESCBC(buffer, password, salt, iv) {
    const key = await deriveKey(password, salt, "AES-CBC");
    return crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, buffer);
}

async function encryptFullAESCTR(data, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(password, salt, "AES-CTR");
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-CTR", counter: iv, length: 64 },
        key,
        data
    );
    return buildHeader(MODE_FULL_AES_CTR, salt, iv, ciphertext);
}

async function decryptFullAESCTR(buffer, password, salt, iv) {
    const key = await deriveKey(password, salt, "AES-CTR");
    return crypto.subtle.decrypt(
        { name: "AES-CTR", counter: iv, length: 64 },
        key,
        buffer
    );
}

async function encryptFullXOR(data, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16)); // not used but kept for uniformity
    const iv = new Uint8Array(0);
    const keyBytes = enc.encode(password);
    const input = new Uint8Array(data);
    const out = new Uint8Array(input.length);
    for (let i = 0; i < input.length; i++) {
        out[i] = input[i] ^ keyBytes[i % keyBytes.length];
    }
    return buildHeader(MODE_FULL_XOR, salt, iv, out.buffer);
}

async function decryptFullXOR(buffer, password, salt, iv) {
    const keyBytes = enc.encode(password);
    const input = new Uint8Array(buffer);
    const out = new Uint8Array(input.length);
    for (let i = 0; i < input.length; i++) {
        out[i] = input[i] ^ keyBytes[i % keyBytes.length];
    }
    return out.buffer;
}

/* ===================== Selective text encryption ===================== */

// For simplicity: handle .txt and .json
// .txt: keep first line plain, encrypt rest as ENC1 header base64
// .json: encrypt each value string/number as ENCVAL:<base64>

async function encryptSelectiveText(filename, data, password) {
    const ext = getFileExtension(filename);
    const text = dec.decode(new Uint8Array(data));

    // ===== TXT =====
    if (ext === FILE_EXTENSIONS.TXT || ext === "") {
        const lines = text.split(REGEX_PATTERNS.NEWLINES);
        const first = lines.shift() ?? "";
        const rest = lines.join("\n");
        const encBuf = await encryptFullAESGCM(enc.encode(rest), password);
        const b64 = btoa(String.fromCharCode(...new Uint8Array(encBuf)));
        const outText = first + "\n" + MARKERS.ENC_BLOCK + b64;
        return new Blob([outText], { type: MIME_TYPES.TEXT });
    }

    // ===== JSON =====
    if (ext === FILE_EXTENSIONS.JSON) {
        let obj;
        try { obj = JSON.parse(text); }
        catch { throw new Error("Invalid JSON for selective mode"); }

        async function encryptValue(v) {
            if (v === null) return v;
            if (typeof v === "object") {
                if (Array.isArray(v)) {
                    const arr = [];
                    for (const item of v) arr.push(await encryptValue(item));
                    return arr;
                } else {
                    const o = {};
                    for (const k of Object.keys(v)) o[k] = await encryptValue(v[k]);
                    return o;
                }
            } else {
                const buf = await encryptFullAESGCM(enc.encode(String(v)), password);
                const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
                return MARKERS.ENCVAL + b64;
            }
        }

        const encObj = await encryptValue(obj);
        return new Blob([JSON.stringify(encObj, null, 2)], { type: MIME_TYPES.JSON });
    }

    // ===== CSV =====
    if (ext === FILE_EXTENSIONS.CSV) {
        const lines = text.split(REGEX_PATTERNS.NEWLINES);
        const outLines = [];

        for (const line of lines) {
            if (!line.trim()) { outLines.push(line); continue; }
            const cells = line.split(",");
            const encCells = [];

            for (const cell of cells) {
                const buf = await encryptFullAESGCM(enc.encode(cell), password);
                const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
                encCells.push(MARKERS.ENCVAL + b64);
            }

            outLines.push(encCells.join(","));
        }

        return new Blob([outLines.join("\n")], { type: MIME_TYPES.CSV });
    }

    // ===== XML =====
    if (ext === FILE_EXTENSIONS.XML) {
        const regex = REGEX_PATTERNS.TEXT_NODES;
        let match, lastIndex = 0, result = "";

        while ((match = regex.exec(text)) !== null) {
            const [full, open, content, close] = match;
            result += text.slice(lastIndex, match.index);

            const trimmed = content.trim();
            if (!trimmed) {
                result += full;
            } else {
                const buf = await encryptFullAESGCM(enc.encode(content), password);
                const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
                result += open + MARKERS.ENCVAL + b64 + close;
            }

            lastIndex = regex.lastIndex;
        }

        result += text.slice(lastIndex);
        return new Blob([result], { type: MIME_TYPES.XML });
    }

    // ===== HTML (encrypt ONLY inside <body>) =====
    if (ext === FILE_EXTENSIONS.HTML || ext === FILE_EXTENSIONS.HTM) {
        const bodyStart = text.toLowerCase().indexOf("<body");
        const bodyEnd = text.toLowerCase().indexOf("</body>");

        if (bodyStart === -1 || bodyEnd === -1) {
            throw new Error("HTML missing <body> tag");
        }

        // Extract <body ...> tag
        const openTagEnd = text.indexOf(">", bodyStart) + 1;
        const beforeBody = text.slice(0, openTagEnd);
        const bodyContent = text.slice(openTagEnd, bodyEnd);
        const afterBody = text.slice(bodyEnd);

        // Encrypt only text nodes inside body
        const regex = REGEX_PATTERNS.TEXT_NODES;
        let match, lastIndex = 0, newBody = "";

        while ((match = regex.exec(bodyContent)) !== null) {
            const [full, open, content, close] = match;
            newBody += bodyContent.slice(lastIndex, match.index);

            const trimmed = content.trim();
            if (!trimmed) {
                newBody += full;
            } else {
                const buf = await encryptFullAESGCM(enc.encode(content), password);
                const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
                newBody += open + MARKERS.ENCVAL + b64 + close;
            }

            lastIndex = regex.lastIndex;
        }

        newBody += bodyContent.slice(lastIndex);

        const finalHTML = beforeBody + newBody + afterBody;
        return new Blob([finalHTML], { type: MIME_TYPES.HTML });
    }

    throw new Error("Selective mode supports .txt, .json, .csv, .xml, .html");
}
async function decryptSelectiveText(filename, data, password) {
    const ext = getFileExtension(filename);
    const text = dec.decode(new Uint8Array(data));

    // ===== TXT =====
    if (ext === FILE_EXTENSIONS.TXT || ext === "") {
        const lines = text.split(REGEX_PATTERNS.NEWLINES);
        if (lines.length === 0) return new Blob([text], { type: MIME_TYPES.TEXT });

        const first = lines.shift();
        const rest = lines.join("\n");

        if (!rest.startsWith(MARKERS.ENC_BLOCK)) {
            return new Blob([text], { type: MIME_TYPES.TEXT });
        }

        const b64 = rest.slice(MARKERS.ENC_BLOCK.length);
        const raw = safeBase64ToBuffer(b64);
        const { salt, iv, ciphertext, modeId } = parseHeader(raw);

        const plainBuf = await decryptFullAESGCM(ciphertext, password, salt, iv);
        const plainRest = dec.decode(new Uint8Array(plainBuf));

        return new Blob([first + "\n" + plainRest], { type: MIME_TYPES.TEXT });
    }

    // ===== JSON =====
    if (ext === FILE_EXTENSIONS.JSON) {
        let obj;
        try { obj = JSON.parse(text); }
        catch { throw new Error("Invalid JSON for selective mode"); }

        async function decryptValue(v) {
            if (v === null) return v;
            if (typeof v === "object") {
                if (Array.isArray(v)) {
                    const arr = [];
                    for (const item of v) arr.push(await decryptValue(item));
                    return arr;
                } else {
                    const o = {};
                    for (const k of Object.keys(v)) o[k] = await decryptValue(v[k]);
                    return o;
                }
            } else if (typeof v === "string" && v.startsWith(MARKERS.ENCVAL)) {
                const b64 = v.slice(MARKERS.ENCVAL.length);
                const raw = safeBase64ToBuffer(b64);
                const { salt, iv, ciphertext } = parseHeader(raw);
                const plainBuf = await decryptFullAESGCM(ciphertext, password, salt, iv);
                return dec.decode(new Uint8Array(plainBuf));
            } else {
                return v;
            }
        }

        const decObj = await decryptValue(obj);
        return new Blob([JSON.stringify(decObj, null, 2)], { type: MIME_TYPES.JSON });
    }

    // ===== CSV =====
    if (ext === FILE_EXTENSIONS.CSV) {
        const lines = text.split(REGEX_PATTERNS.NEWLINES);
        const outLines = [];

        for (const line of lines) {
            if (!line.trim()) { outLines.push(line); continue; }

            const cells = line.split(",");
            const decCells = [];

            for (const cell of cells) {
                const trimmed = cell.trim();
                if (!trimmed.startsWith(MARKERS.ENCVAL)) {
                    decCells.push(cell);
                    continue;
                }

                const b64 = trimmed.slice(MARKERS.ENCVAL.length);
                const raw = safeBase64ToBuffer(b64);
                const { salt, iv, ciphertext } = parseHeader(raw);
                const plainBuf = await decryptFullAESGCM(ciphertext, password, salt, iv);
                decCells.push(dec.decode(new Uint8Array(plainBuf)));
            }

            outLines.push(decCells.join(","));
        }

        return new Blob([outLines.join("\n")], { type: MIME_TYPES.CSV });
    }

    // ===== XML =====
    if (ext === FILE_EXTENSIONS.XML) {
        const regex = REGEX_PATTERNS.TEXT_NODES;
        let match, lastIndex = 0, result = "";

        while ((match = regex.exec(text)) !== null) {
            const [full, open, content, close] = match;
            result += text.slice(lastIndex, match.index);

            const trimmed = content.trim();
            if (trimmed.startsWith(MARKERS.ENCVAL)) {
                const b64 = trimmed.slice(MARKERS.ENCVAL.length);
                const raw = safeBase64ToBuffer(b64);
                const { salt, iv, ciphertext } = parseHeader(raw);
                const plainBuf = await decryptFullAESGCM(ciphertext, password, salt, iv);
                result += open + dec.decode(new Uint8Array(plainBuf)) + close;
            } else {
                result += full;
            }

            lastIndex = regex.lastIndex;
        }

        result += text.slice(lastIndex);
        return new Blob([result], { type: MIME_TYPES.XML });
    }

    // ===== HTML (decrypt ONLY inside <body>) =====
    if (ext === FILE_EXTENSIONS.HTML || ext === FILE_EXTENSIONS.HTM) {
        const bodyStart = text.toLowerCase().indexOf("<body");
        const bodyEnd = text.toLowerCase().indexOf("</body>");

        if (bodyStart === -1 || bodyEnd === -1) {
            throw new Error("HTML missing <body> tag");
        }

        const openTagEnd = text.indexOf(">", bodyStart) + 1;
        const beforeBody = text.slice(0, openTagEnd);
        const bodyContent = text.slice(openTagEnd, bodyEnd);
        const afterBody = text.slice(bodyEnd);

        const regex = REGEX_PATTERNS.TEXT_NODES;
        let match, lastIndex = 0, newBody = "";

        while ((match = regex.exec(bodyContent)) !== null) {
            const [full, open, content, close] = match;
            newBody += bodyContent.slice(lastIndex, match.index);

            const trimmed = content.trim();
            if (trimmed.startsWith(MARKERS.ENCVAL)) {
                const b64 = trimmed.slice(MARKERS.ENCVAL.length);
                const raw = safeBase64ToBuffer(b64);
                const { salt, iv, ciphertext } = parseHeader(raw);
                const plainBuf = await decryptFullAESGCM(ciphertext, password, salt, iv);
                newBody += open + dec.decode(new Uint8Array(plainBuf)) + close;
            } else {
                newBody += full;
            }

            lastIndex = regex.lastIndex;
        }

        newBody += bodyContent.slice(lastIndex);

        return new Blob([beforeBody + newBody + afterBody], { type: MIME_TYPES.HTML });
    }

    throw new Error("Selective mode supports .txt, .json, .csv, .xml, .html");
}
/* ===================== Embedded encrypted block ===================== */

async function encryptEmbeddedBlock(filename, data, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt, "AES-GCM");
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
    const headerBuf = buildHeader(MODE_FULL_AES_GCM, salt, iv, ciphertext);
    const b64 = btoa(String.fromCharCode(...new Uint8Array(headerBuf)));

    const markerStart = "\n" + MARKERS.EMBEDDED_START + "\n";
    const markerEnd = "\n" + MARKERS.EMBEDDED_END + "\n";
    const block = markerStart + b64 + markerEnd;

    const original = new Uint8Array(data);
    const blockBytes = enc.encode(block);
    const combined = new Uint8Array(original.length + blockBytes.length);
    combined.set(original, 0);
    combined.set(blockBytes, original.length);

    return new Blob([combined], { type: MIME_TYPES.BINARY });
}

async function decryptEmbeddedBlock(filename, data, password) {
    const text = dec.decode(new Uint8Array(data));
    const start = text.indexOf(MARKERS.EMBEDDED_START);
    const end = text.indexOf(MARKERS.EMBEDDED_END);
    if (start === -1 || end === -1) {
        throw new Error("No embedded block found");
    }
    const b64 = text.slice(
        text.indexOf("\n", start) + 1,
        text.lastIndexOf("\n", end)
    ).trim();
    const raw = safeBase64ToBuffer(b64);
    const { salt, iv, ciphertext, modeId } = parseHeader(raw);
    if (modeId !== MODE_FULL_AES_GCM) throw new Error("Unexpected mode in embedded block");
    const plainBuf = await decryptFullAESGCM(ciphertext, password, salt, iv);
    return new Blob([plainBuf], { type: MIME_TYPES.BINARY });
}

/* ===================== PNG stego – metadata (trailing data) ===================== */

async function encryptStegoPngMeta(filename, data, password) {
    const ext = getFileExtension(filename);
    if (ext !== FILE_EXTENSIONS.PNG) throw new Error("PNG metadata stego requires a .png file");

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt, "AES-GCM");
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
    const headerBuf = buildHeader(MODE_FULL_AES_GCM, salt, iv, ciphertext);
    const b64 = btoa(String.fromCharCode(...new Uint8Array(headerBuf)));

    const marker = "\n" + MARKERS.PNG_STEGO;
    const markerBytes = enc.encode(marker + b64);

    const original = new Uint8Array(data);
    const combined = new Uint8Array(original.length + markerBytes.length);
    combined.set(original, 0);
    combined.set(markerBytes, original.length);

    return new Blob([combined], { type: MIME_TYPES.PNG });
}

async function decryptStegoPngMeta(filename, data, password) {
    const bytes = new Uint8Array(data);
    const marker = enc.encode(MARKERS.PNG_STEGO);
    // search from end
    let pos = -1;
    for (let i = bytes.length - marker.length; i >= 0; i--) {
        let ok = true;
        for (let j = 0; j < marker.length; j++) {
            if (bytes[i + j] !== marker[j]) { ok = false; break; }
        }
        if (ok) { pos = i; break; }
    }
    if (pos === -1) throw new Error("No PNG stego metadata found");
    const b64Bytes = bytes.slice(pos + marker.length);
    const b64 = dec.decode(b64Bytes);
    const raw = safeBase64ToBuffer(b64);
    const { salt, iv, ciphertext, modeId } = parseHeader(raw);
    if (modeId !== MODE_FULL_AES_GCM) throw new Error("Unexpected mode in PNG stego meta");
    const plainBuf = await decryptFullAESGCM(ciphertext, password, salt, iv);
    return new Blob([plainBuf], { type: MIME_TYPES.BINARY });
}

/* ===================== PNG stego – LSB pixels (with fallback) ===================== */

function loadImageFromArrayBuffer(buffer) {
    return new Promise((resolve, reject) => {
        try {
            const blob = new Blob([buffer], { type: MIME_TYPES.PNG });
            const url = URL.createObjectURL(blob);
            const img = new Image();
            
            img.onload = () => {
                try {
                    URL.revokeObjectURL(url);
                    resolve(img);
                } catch (err) {
                    reject(new Error("Failed to cleanup image URL: " + err.message));
                }
            };
            
            img.onerror = () => {
                try {
                    URL.revokeObjectURL(url);
                } catch (e) {
                    /* silently ignore cleanup errors */
                }
                reject(new Error("Failed to load image - invalid PNG or corrupted data"));
            };
            
            img.onabort = () => {
                try {
                    URL.revokeObjectURL(url);
                } catch (e) {
                    /* silently ignore cleanup errors */
                }
                reject(new Error("Image loading aborted"));
            };
            
            img.src = url;
        } catch (err) {
            reject(new Error("Failed to create image blob: " + err.message));
        }
    });
}

function bitsFromBytes(bytes) {
    const bits = [];
    for (let i = 0; i < bytes.length; i++) {
        for (let b = 7; b >= 0; b--) {
            bits.push((bytes[i] >> b) & 1);
        }
    }
    return bits;
}

function bytesFromBits(bits) {
    const len = Math.floor(bits.length / 8);
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        let v = 0;
        for (let b = 0; b < 8; b++) {
            v = (v << 1) | bits[i * 8 + b];
        }
        out[i] = v;
    }
    return out;
}

async function encryptStegoPngLSB(filename, data, password) {
    const ext = getFileExtension(filename);
    if (ext !== FILE_EXTENSIONS.PNG) throw new Error("PNG LSB stego requires a .png file");

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt, "AES-GCM");
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
    const headerBuf = buildHeader(MODE_FULL_AES_GCM, salt, iv, ciphertext);

    // payload = magic + headerBuf
    const magic = enc.encode(MARKERS.LSB_STEGO);
    const payload = new Uint8Array(magic.length + headerBuf.byteLength);
    payload.set(magic, 0);
    payload.set(new Uint8Array(headerBuf), magic.length);

    const bits = bitsFromBytes(payload);

    try {
        const img = await loadImageFromArrayBuffer(data);
        const canvas = document.createElement("canvas");
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext("2d");
        
        if (!ctx) throw new Error("Failed to get 2D canvas context");
        
        ctx.drawImage(img, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const pixels = imageData.data; // RGBA

        const capacity = Math.floor(pixels.length / 4) * 3; // use R,G,B LSB
        if (bits.length > capacity) {
            // overflow -> fallback to metadata stego
            return encryptStegoPngMeta(filename, data, password);
        }

        let bitIndex = 0;
        for (let i = 0; i < pixels.length && bitIndex < bits.length; i += 4) {
            for (let c = 0; c < 3 && bitIndex < bits.length; c++) {
                pixels[i + c] = (pixels[i + c] & 0xFE) | bits[bitIndex++];
            }
        }
        ctx.putImageData(imageData, 0, 0);

        const stegoBlob = await new Promise(resolve => canvas.toBlob(resolve, MIME_TYPES.PNG));
        return stegoBlob;
    } catch (err) {
        throw new Error("LSB stego encoding failed: " + err.message);
    }
}

async function decryptStegoPngLSB(filename, data, password) {
    const ext = getFileExtension(filename);
    if (ext !== FILE_EXTENSIONS.PNG) throw new Error("PNG LSB stego requires a .png file");

    try {
        const img = await loadImageFromArrayBuffer(data);
        const canvas = document.createElement("canvas");
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext("2d");
        
        if (!ctx) throw new Error("Failed to get 2D canvas context");
        
        ctx.drawImage(img, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const pixels = imageData.data;

        const bits = [];
        for (let i = 0; i < pixels.length; i += 4) {
            for (let c = 0; c < 3; c++) {
                bits.push(pixels[i + c] & 1);
            }
        }
        const bytes = bytesFromBits(bits);

        const magic = enc.encode(MARKERS.LSB_STEGO);
        let ok = true;
        if (bytes.length < magic.length) ok = false;
        else {
            for (let i = 0; i < magic.length; i++) {
                if (bytes[i] !== magic[i]) { ok = false; break; }
            }
        }
        if (!ok) throw new Error("No LSB stego payload found");

        const headerBytes = bytes.slice(magic.length);
        const headerBuf = headerBytes.buffer;
        const { salt, iv, ciphertext, modeId } = parseHeader(headerBuf);
        if (modeId !== MODE_FULL_AES_GCM) throw new Error("Unexpected mode in PNG LSB stego");
        const plainBuf = await decryptFullAESGCM(ciphertext, password, salt, iv);
        return new Blob([plainBuf], { type: MIME_TYPES.BINARY });
    } catch (err) {
        throw new Error("LSB stego decoding failed: " + err.message);
    }
}


/* ===================== Symbol Vault authenticated format ===================== */
const SYMBOL_VAULT_MAGIC = "CF★2";
const SYMBOL_ALPHABET = ["★","✔","♡","ℳ","∺","∎","～","❥","☑"];
const SYMBOL_PBKDF2_ITERATIONS = 600000;
function bytesToSymbols(bytes){let value=0,bits=0,out="";for(const b of bytes){value=(value<<8)|b;bits+=8;while(bits>=3){bits-=3;out+=SYMBOL_ALPHABET[(value>>bits)&7];value&=(1<<bits)-1}}if(bits>0)out+=SYMBOL_ALPHABET[(value<<(3-bits))&7];return out}
function symbolsToBytes(text){const clean=Array.from(text).filter(c=>SYMBOL_ALPHABET.includes(c));let value=0,bits=0,out=[];for(const symbol of clean){const n=SYMBOL_ALPHABET.indexOf(symbol);if(n<0||n>7)throw new Error("Invalid Symbol Vault character");value=(value<<3)|n;bits+=3;while(bits>=8){bits-=8;out.push((value>>bits)&255);value&=(1<<bits)-1}}return new Uint8Array(out)}
async function deriveSymbolVaultKey(password,salt){const material=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:SYMBOL_PBKDF2_ITERATIONS,hash:"SHA-256"},material,{name:"AES-GCM",length:256},false,["encrypt","decrypt"])}
async function encryptSymbolVault(file,data,password){if(password.length!==256)throw new Error("Symbol Vault requires a password of exactly 256 characters");const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12)),key=await deriveSymbolVaultKey(password,salt);const meta=enc.encode(JSON.stringify({name:file.name,type:file.type||"application/octet-stream",size:data.byteLength}));const plain=new Uint8Array(4+meta.length+data.byteLength),view=new DataView(plain.buffer);view.setUint32(0,meta.length);plain.set(meta,4);plain.set(new Uint8Array(data),4+meta.length);const aad=enc.encode("CryptForge Symbol Vault v2");const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:aad,tagLength:128},key,plain);const payload=new Uint8Array(16+12+cipher.byteLength);payload.set(salt,0);payload.set(iv,16);payload.set(new Uint8Array(cipher),28);const wrapped=`${SYMBOL_VAULT_MAGIC}\n${bytesToSymbols(payload)}`;return {blob:new Blob([wrapped],{type:"text/plain;charset=utf-8"}),filename:file.name+".cfstar"}}
async function decryptSymbolVault(file,data,password){const text=dec.decode(new Uint8Array(data));if(!text.startsWith(SYMBOL_VAULT_MAGIC))throw new Error("This is not a CryptForge Symbol Vault file");if(password.length!==256)throw new Error("Symbol Vault requires a password of exactly 256 characters");const payload=symbolsToBytes(text.slice(SYMBOL_VAULT_MAGIC.length));if(payload.length<45)throw new Error("Symbol Vault file is incomplete");const salt=payload.slice(0,16),iv=payload.slice(16,28),cipher=payload.slice(28),key=await deriveSymbolVaultKey(password,salt),aad=enc.encode("CryptForge Symbol Vault v2");let plain;try{plain=await crypto.subtle.decrypt({name:"AES-GCM",iv,additionalData:aad,tagLength:128},key,cipher)}catch{throw new Error("Wrong password or modified Symbol Vault data")};const bytes=new Uint8Array(plain),view=new DataView(plain),metaLen=view.getUint32(0);if(metaLen<2||metaLen>bytes.length-4)throw new Error("Invalid Symbol Vault metadata");const meta=JSON.parse(dec.decode(bytes.slice(4,4+metaLen)));return {blob:new Blob([bytes.slice(4+metaLen)],{type:meta.type}),filename:meta.name||file.name.replace(/\.cfstar$/i,"")}}

/* ===================== Dispatcher ===================== */

async function encryptDispatcher(algo, file, data, password) {
    const name = file.name;
    switch (algo) {
        case "symbol-vault": return encryptSymbolVault(file, data, password);
        case "full-aes-gcm": {
            const buf = await encryptFullAESGCM(data, password);
            return { blob: new Blob([buf]), filename: name + "." + FILE_EXTENSIONS.ENC };
        }
        case "full-aes-cbc": {
            const buf = await encryptFullAESCBC(data, password);
            return { blob: new Blob([buf]), filename: name + "." + FILE_EXTENSIONS.ENC };
        }
        case "full-aes-ctr": {
            const buf = await encryptFullAESCTR(data, password);
            return { blob: new Blob([buf]), filename: name + "." + FILE_EXTENSIONS.ENC };
        }
        case "full-xor": {
            const buf = await encryptFullXOR(data, password);
            return { blob: new Blob([buf]), filename: name + "." + FILE_EXTENSIONS.ENC };
        }
        case "selective-text": {
            const blob = await encryptSelectiveText(name, data, password);
            return { blob, filename: transformFilename(name, "_selenc$1") };
        }
        case "embedded-block": {
            const blob = await encryptEmbeddedBlock(name, data, password);
            return { blob, filename: transformFilename(name, "_emb$1") };
        }
        case "stego-png-meta": {
            const blob = await encryptStegoPngMeta(name, data, password);
            return { blob, filename: transformFilename(name, "_meta.png") };
        }
        case "stego-png-lsb": {
            const blob = await encryptStegoPngLSB(name, data, password);
            return { blob, filename: transformFilename(name, "_lsb.png") };
        }
        default:
            throw new Error("Unknown encryption mode");
    }
}

async function decryptDispatcher(algo, file, data, password) {
    const name = file.name;
    switch (algo) {
        case "symbol-vault": return decryptSymbolVault(file, data, password);
        case "full-aes-gcm":
        case "full-aes-cbc":
        case "full-aes-ctr":
        case "full-xor": {
            const { modeId, salt, iv, ciphertext } = parseHeader(data);
            let plain;
            if (modeId === MODE_FULL_AES_GCM) {
                plain = await decryptFullAESGCM(ciphertext, password, salt, iv);
            } else if (modeId === MODE_FULL_AES_CBC) {
                plain = await decryptFullAESCBC(ciphertext, password, salt, iv);
            } else if (modeId === MODE_FULL_AES_CTR) {
                plain = await decryptFullAESCTR(ciphertext, password, salt, iv);
            } else if (modeId === MODE_FULL_XOR) {
                plain = await decryptFullXOR(ciphertext, password, salt, iv);
            } else {
                throw new Error("Unsupported mode in header");
            }
            const outName = name.replace(new RegExp("\\." + FILE_EXTENSIONS.ENC + "$"), "") || ("decrypted_" + name);
            return { blob: new Blob([plain]), filename: outName };
        }
        case "selective-text": {
            const blob = await decryptSelectiveText(name, data, password);
            const outName = name.replace("_selenc", "");
            return { blob, filename: outName };
        }
        case "embedded-block": {
            const blob = await decryptEmbeddedBlock(name, data, password);
            const outName = name.replace("_emb", "");
            return { blob, filename: outName };
        }
        case "stego-png-meta": {
            const blob = await decryptStegoPngMeta(name, data, password);
            const outName = "stego_meta_decrypted_" + name;
            return { blob, filename: outName };
        }
        case "stego-png-lsb": {
            const blob = await decryptStegoPngLSB(name, data, password);
            const outName = "stego_lsb_decrypted_" + name;
            return { blob, filename: outName };
        }
        default:
            throw new Error("Unknown decryption mode");
    }
}

/* ===================== V4 developer utilities ===================== */
const TOOL_MODES = new Set(["js-obfuscate","js-minify","base64-encode","base64-decode","sha256"]);
function textToBase64(text){const bytes=new TextEncoder().encode(text);let binary="";for(let i=0;i<bytes.length;i+=0x8000)binary+=String.fromCharCode(...bytes.subarray(i,i+0x8000));return btoa(binary)}
function base64ToText(value){const clean=value.replace(/\s+/g,"");const binary=atob(clean);const bytes=Uint8Array.from(binary,c=>c.charCodeAt(0));return new TextDecoder().decode(bytes)}
function minifyJavaScript(code){return code.replace(/\/\*[\s\S]*?\*\//g,"").replace(/(^|[^:])\/\/.*$/gm,"$1").replace(/\s+/g," ").replace(/\s*([{}();,:+*=<>\[\]])\s*/g,"$1").trim()}
function obfuscateJavaScript(code){const packed=textToBase64(code);const chunks=packed.match(/.{1,76}/g)||[];return `/* CryptForge V4 obfuscated JavaScript. Obfuscation discourages casual reading but is not encryption. */\n(()=>{const _0xC=${JSON.stringify(chunks)}.join('');const _0xB=atob(_0xC);const _0xU=Uint8Array.from(_0xB,_0xQ=>_0xQ.charCodeAt(0));(0,eval)(new TextDecoder().decode(_0xU));})();`}
async function runUtility(mode,file,data){const text=new TextDecoder().decode(new Uint8Array(data));if(mode==="js-obfuscate"){if(!/\.(m?js)$/i.test(file.name))throw new Error("JavaScript Obfuscation requires a .js or .mjs file");return {text:obfuscateJavaScript(text),filename:file.name.replace(/\.(m?js)$/i,".obfuscated.$1")}}if(mode==="js-minify"){if(!/\.(m?js)$/i.test(file.name))throw new Error("JavaScript Minifier requires a .js or .mjs file");return {text:minifyJavaScript(text),filename:file.name.replace(/\.(m?js)$/i,".min.$1")}}if(mode==="base64-encode")return {text:textToBase64(text),filename:file.name+".base64.txt"};if(mode==="base64-decode")return {text:base64ToText(text),filename:file.name.replace(/\.base64\.txt$/i,"")||"decoded.txt"};if(mode==="sha256"){const digest=await crypto.subtle.digest("SHA-256",data);const hash=[...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,"0")).join("");return {text:hash,filename:file.name+".sha256.txt"}}throw new Error("Unknown utility mode")}
/* ===================== CryptForge Pro interface ===================== */
(() => {
const $=id=>document.getElementById(id),fileInput=$('fileInput'),processBtn=$('processBtn'),processText=$('processText'),fileInspector=$('fileInspector'),fileBadge=$('fileBadge'),fileName=$('fileName'),fileDetails=$('fileDetails'),methodHelp=$('methodHelp'),passwordSection=$('passwordSection'),strengthBar=$('strengthBar'),strengthText=$('strengthText'),passwordLength=$('passwordLength'),progressPanel=$('progressPanel'),progressBar=$('progressBar'),progressPercent=$('progressPercent'),progressLabel=$('progressLabel'),resultPanel=$('resultPanel'),resultPreview=$('resultPreview'),historyList=$('historyList');
let selectedFile=null,lastResult=null,history=[];
const descriptions={"symbol-vault":"CryptForge-exclusive CF★2 container using AES-256-GCM, a 600,000-round PBKDF2-SHA-256 key, authenticated metadata, exactly 256 password characters, and the visual alphabet ★ ✔ ♡ ℳ ∺ ∎ ～ ❥ ☑. Symbols are encoding; AES-GCM provides security.","full-aes-gcm":"Authenticated AES-256 encryption. Recommended because modifications and incorrect passwords are detected.","full-aes-cbc":"AES-256 block encryption. Compatible, but does not authenticate the output.","full-aes-ctr":"AES-256 counter mode for stream-like processing. Does not authenticate the output.","selective-text":"Encrypts values or text regions while retaining the surrounding document structure.","embedded-block":"Appends an encrypted copy of the selected data inside a marked block.","stego-png-meta":"Stores encrypted data after the PNG stream. Some image processors may remove it.","stego-png-lsb":"Hides encrypted data in pixel color bits. Requires a PNG with enough capacity.","js-obfuscate":"Transforms .js or .mjs source into a self-decoding wrapper. Obfuscation is reversible and is not encryption.","js-minify":"Removes comments and extra whitespace from JavaScript. Review the output because regex-based minification has limits.","base64-encode":"Encodes text as Base64 for transport. Base64 provides no confidentiality.","base64-decode":"Decodes Base64 text into readable UTF-8 text.",sha256:"Creates a SHA-256 integrity fingerprint for any selected file.","full-xor":"Legacy XOR transformation. This is weak and should not protect sensitive data."};
const grades={"symbol-vault":["A+","good"],"full-aes-gcm":["A+","good"],"full-aes-cbc":["B","warn"],"full-aes-ctr":["B","warn"],"full-xor":["D","bad"]};
const format=n=>n<1024?`${n} B`:n<1048576?`${(n/1024).toFixed(1)} KB`:`${(n/1048576).toFixed(2)} MB`;
function isTool(){return TOOL_MODES.has(algoSelect.value)}
function setStatus(text,type=''){output.textContent=text;output.className=type}
function updateMethod(){methodHelp.textContent=descriptions[algoSelect.value]||'Local file operation.';passwordSection.classList.toggle('mutedControl',isTool());const g=grades[algoSelect.value]||[isTool()?'TOOL':'A',''];$('securityGrade').textContent=g[0];$('securityGrade').style.background=g[1]==='bad'?'var(--red)':g[1]==='warn'?'var(--amber)':'var(--green)';updateButton()}
function updateButton(){const required=algoSelect.value==='symbol-vault'?256:MIN_PASSWORD_LENGTH;const ready=selectedFile&&(isTool()||(algoSelect.value==='symbol-vault'?passwordInput.value.length===256:passwordInput.value.length>=required));processBtn.disabled=!ready;processText.textContent=!selectedFile?'Select a file to continue':!isTool()&&passwordInput.value.length<(algoSelect.value==='symbol-vault'?256:MIN_PASSWORD_LENGTH)?(algoSelect.value==='symbol-vault'?'Enter exactly 256 password characters':'Enter a password to continue'):isTool()?'Run developer tool':mode==='encrypt'?'Encrypt and download':'Decrypt and download'}
function selectFile(file){if(!file)return;if(file.size>MAX_FILE_SIZE){setStatus('File exceeds the 500 MB limit.','error');return}selectedFile=file;fileName.textContent=file.name;fileDetails.textContent=`${format(file.size)} · ${file.type||'Unknown type'} · Modified ${new Date(file.lastModified).toLocaleDateString()}`;fileInspector.classList.remove('hidden');fileBadge.textContent='READY';fileBadge.classList.add('ready');updateButton()}
function clearFile(){selectedFile=null;fileInput.value='';fileInspector.classList.add('hidden');fileBadge.textContent='EMPTY';fileBadge.classList.remove('ready');resultPanel.classList.add('hidden');setStatus('');updateButton()}
function addHistory(name,method,status){history.unshift({name,method,status,time:new Date()});history=history.slice(0,20);renderHistory()}
function renderHistory(){historyList.innerHTML=history.length?history.map(h=>`<div class="historyItem"><div><b>${escapeHtml(h.name)}</b><span>${escapeHtml(h.method)} · ${h.status}</span></div><time>${h.time.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}</time></div>`).join(''):'<div class="emptyState">No operations in this session yet.</div>'}
function escapeHtml(v){return String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function saveDownload(blob,filename){const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=filename;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),2000)}
download=saveDownload;
function animateProgress(){progressPanel.classList.remove('hidden');let value=5;progressBar.style.width='5%';progressPercent.textContent='5%';const timer=setInterval(()=>{value=Math.min(92,value+Math.random()*12);progressBar.style.width=value+'%';progressPercent.textContent=Math.floor(value)+'%'},180);return()=>{clearInterval(timer);progressBar.style.width='100%';progressPercent.textContent='100%';setTimeout(()=>progressPanel.classList.add('hidden'),450)}}
async function process(){if(!selectedFile)return;processBtn.disabled=true;const done=animateProgress();progressLabel.textContent=isTool()?'Running local transformation':'Processing securely';setStatus('Working locally…');try{const data=await selectedFile.arrayBuffer();let result,preview='';if(isTool()){const out=await runUtility(algoSelect.value,selectedFile,data);preview=out.text;result={blob:new Blob([out.text],{type:'text/plain;charset=utf-8'}),filename:out.filename}}else{validateInput(passwordInput.value,data);result=mode==='encrypt'?await encryptDispatcher(algoSelect.value,selectedFile,data,passwordInput.value):await decryptDispatcher(algoSelect.value,selectedFile,data,passwordInput.value)}if(!result)throw new Error('No output was produced');lastResult=result;saveDownload(result.blob,result.filename);resultPreview.textContent=preview?preview.slice(0,18000):`Output file: ${result.filename}\nSize: ${format(result.blob.size)}\nOperation completed successfully.`;resultPanel.classList.remove('hidden');setStatus(`Completed successfully: ${result.filename}`,'success');addHistory(selectedFile.name,algoSelect.options[algoSelect.selectedIndex].text,'Success')}catch(err){console.error(err);setStatus(`Operation failed: ${err.message||'Unknown error'}`,'error');addHistory(selectedFile.name,algoSelect.options[algoSelect.selectedIndex].text,'Failed')}finally{done();updateButton()}}
function selectMode(next){mode=next;[$('encryptMode'),$('decryptMode'),$('toolsMode')].forEach(b=>b.classList.remove('active'));if(next==='tools'){$('toolsMode').classList.add('active');if(!isTool())algoSelect.value='js-obfuscate'}else{$(next+'Mode').classList.add('active');if(isTool())algoSelect.value='full-aes-gcm'}updateMethod()}
$('encryptMode').onclick=()=>selectMode('encrypt');$('decryptMode').onclick=()=>selectMode('decrypt');$('toolsMode').onclick=()=>selectMode('tools');
dropzone.addEventListener('dragover',e=>{e.preventDefault();dropzone.classList.add('dragover')});dropzone.addEventListener('dragleave',()=>dropzone.classList.remove('dragover'));dropzone.addEventListener('drop',e=>{e.preventDefault();dropzone.classList.remove('dragover');selectFile(e.dataTransfer.files[0])});dropzone.onclick=()=>fileInput.click();dropzone.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();fileInput.click()}};fileInput.onchange=()=>selectFile(fileInput.files[0]);$('removeFile').onclick=clearFile;$('clearBtn').onclick=()=>{clearFile();passwordInput.value='';updateStrength()};algoSelect.onchange=updateMethod;processBtn.onclick=process;$('togglePassword').onclick=()=>{const show=passwordInput.type==='password';passwordInput.type=show?'text':'password';$('togglePassword').textContent=show?'Hide':'Show'};
function updateStrength(){const p=passwordInput.value;let score=0;if(p.length>=8)score++;if(p.length>=12)score++;if(/[a-z]/.test(p)&&/[A-Z]/.test(p))score++;if(/\d/.test(p)&&/[^\w]/.test(p))score++;const labels=['No password entered','Weak','Fair','Strong','Excellent'],colors=['var(--red)','var(--red)','var(--amber)','var(--blue)','var(--green)'];strengthBar.style.width=(score*25)+'%';strengthBar.style.background=colors[score];strengthText.textContent=p?labels[Math.max(1,score)]:'No password entered';passwordLength.textContent=`${p.length} chars`;updateButton()}passwordInput.oninput=updateStrength;
$('copyResult').onclick=async()=>{try{await navigator.clipboard.writeText(resultPreview.textContent);$('copyResult').textContent='Copied';setTimeout(()=>$('copyResult').textContent='Copy preview',1200)}catch{setStatus('Clipboard access is unavailable in this browser context.','error')}};$('downloadAgain').onclick=()=>lastResult&&saveDownload(lastResult.blob,lastResult.filename);$('clearHistory').onclick=()=>{history=[];renderHistory()};
document.querySelectorAll('.nav').forEach(btn=>btn.onclick=()=>{document.querySelectorAll('.nav').forEach(b=>b.classList.remove('active'));btn.classList.add('active');document.querySelectorAll('.view').forEach(v=>v.classList.add('hidden'));$(btn.dataset.view+'View').classList.remove('hidden');$('viewTitle').textContent={workspace:'Secure workspace',history:'Session activity',about:'Security center'}[btn.dataset.view]});$('themeBtn').onclick=()=>{const root=document.documentElement;root.dataset.theme=root.dataset.theme==='dark'?'light':'dark'};$('sessionId').textContent=Math.random().toString(16).slice(2,8).toUpperCase();renderHistory();updateMethod();updateStrength();
})();
