import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, rm, stat, unlink, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const uploadDirectory = resolve(projectRoot, "data", "courtroom", "uploads");
const port = Number(process.env.PORT || process.env.COURTROOM_PORT || 4173);
const production = process.env.NODE_ENV === "production";
const maximumBodyBytes = 42 * 1024 * 1024;
const maximumAttachmentBytes = 30 * 1024 * 1024;
const maximumStoredBytes = 250 * 1024 * 1024;
const maximumMessagesPerSide = 100;
const maximumActiveRooms = 100;
const sessionDurationSeconds = 12 * 60 * 60;
const sessionSecret = process.env.COURT_SESSION_SECRET || (production ? "" : randomBytes(32).toString("hex"));
const roleNames = { judge: "판사", victim: "피해자", suspect: "피의자" };
const roleSides = { victim: "victim", suspect: "suspect" };
const roomCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

if (!sessionSecret) {
  console.error("Set COURT_SESSION_SECRET before starting in production.");
  process.exit(1);
}

const assets = new Map([
  ["/", { file: "index.html", type: "text/html; charset=utf-8" }],
  ["/index.html", { file: "index.html", type: "text/html; charset=utf-8" }],
  ["/style.css", { file: "style.css", type: "text/css; charset=utf-8" }],
  ["/script.js", { file: "script.js", type: "text/javascript; charset=utf-8" }]
]);
const mediaTypes = new Map([
  ["image/jpeg", "jpg"], ["image/png", "png"], ["image/gif", "gif"], ["image/webp", "webp"],
  ["image/avif", "avif"], ["image/bmp", "bmp"], ["image/heic", "heic"],
  ["video/mp4", "mp4"], ["video/webm", "webm"], ["video/quicktime", "mov"],
  ["video/x-msvideo", "avi"]
]);

const rooms = new Map();
const mediaIndex = new Map();
const subscribers = new Set();
const loginFailures = new Map();
const messageRates = new Map();
let storedBytes = 0;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function signSession(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", sessionSecret).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

function sessionFromRequest(request) {
  const cookieHeader = request.headers.cookie || "";
  const sessionCookie = cookieHeader.split(";").map((part) => part.trim()).find((part) => part.startsWith("court_session="));
  if (!sessionCookie) return null;
  const token = sessionCookie.slice("court_session=".length);
  const [encoded, signature] = token.split(".");
  if (!encoded || !signature) return null;
  const expected = createHmac("sha256", sessionSecret).update(encoded).digest();
  let supplied;
  try {
    supplied = Buffer.from(signature, "base64url");
  } catch {
    return null;
  }
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    if (!Object.hasOwn(roleNames, payload.role) || payload.expiresAt <= Date.now() || !rooms.has(payload.roomCode)) return null;
    return payload;
  } catch {
    return null;
  }
}

function canReadSide(session, side) {
  return Boolean(session && (side === "victim" || side === "suspect") && rooms.get(session.roomCode)?.messages[side]);
}

function canSendSide(session, side) {
  return session?.role === "judge" || (Object.hasOwn(roleSides, session?.role) && roleSides[session.role] === side);
}

function makeRoomCode() {
  let code = "";
  const bytes = randomBytes(8);
  for (const byte of bytes) code += roomCodeAlphabet[byte & 31];
  return code.slice(0, 4) + "-" + code.slice(4);
}

function normalizeRoomCode(value) {
  const code = String(value || "").replace(/[\s-]/g, "").toUpperCase();
  return /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$/.test(code) ? code : "";
}

function formatRoomCode(code) {
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

function createRoomState() {
  const createdAt = new Date().toISOString();
  return {
    createdAt,
    messages: {
      victim: [{
        id: randomUUID(), side: "victim", type: "system",
        text: "피해자 측 대화방입니다. 양측 참여자는 서로의 대화를 볼 수 있습니다.",
        createdAt
      }],
      suspect: [{
        id: randomUUID(), side: "suspect", type: "system",
        text: "피의자 측 대화방입니다. 양측 참여자는 서로의 대화를 볼 수 있습니다.",
        createdAt
      }]
    }
  };
}

function createSession(role, name, roomCode) {
  return {
    role,
    name: safeName(name, roleNames[role]),
    roomCode,
    sessionId: randomUUID(),
    expiresAt: Date.now() + sessionDurationSeconds * 1000
  };
}

function json(response, status, value, headers = {}) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...headers
  });
  response.end(JSON.stringify(value));
}

async function readJson(request, limit = maximumBodyBytes) {
  const contentLength = Number(request.headers["content-length"] || 0);
  if (contentLength > limit) {
    request.resume();
    throw new HttpError(413, "첨부 파일 합계는 메시지당 30MB까지 가능합니다.");
  }
  const chunks = [];
  let size = 0;
  let tooLarge = false;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > limit) {
      tooLarge = true;
      continue;
    }
    chunks.push(chunk);
  }
  if (tooLarge) throw new HttpError(413, "요청 크기가 허용 범위를 초과했습니다.");
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "요청 내용을 읽을 수 없습니다.");
  }
}

function clientAddress(request) {
  const forwarded = request.headers["x-forwarded-for"];
  return typeof forwarded === "string" ? forwarded.split(",")[0].trim() : request.socket.remoteAddress || "unknown";
}

function recordLoginFailure(address) {
  const now = Date.now();
  const attempts = (loginFailures.get(address) || []).filter((time) => now - time < 60_000);
  attempts.push(now);
  loginFailures.set(address, attempts);
  return attempts.length;
}

function allowMessageRate(session) {
  const now = Date.now();
  const recent = (messageRates.get(session.sessionId) || []).filter((time) => now - time < 60_000);
  if (recent.length >= 60) return false;
  recent.push(now);
  messageRates.set(session.sessionId, recent);
  return true;
}

function safeName(value, fallback) {
  const cleaned = String(value || "").replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 20);
  return cleaned || fallback;
}

function cleanFileName(value) {
  const cleaned = String(value || "첨부파일").replace(/[\\/\u0000-\u001f\u007f]/g, "_").trim().slice(0, 120);
  return cleaned || "첨부파일";
}

function validateAttachments(attachments) {
  if (!Array.isArray(attachments)) throw new HttpError(400, "첨부 파일 형식이 올바르지 않습니다.");
  if (attachments.length > 5) throw new HttpError(400, "메시지 하나에 파일을 최대 5개까지 첨부할 수 있습니다.");
  let totalBytes = 0;
  const validated = attachments.map((attachment) => {
    const type = String(attachment?.type || "").toLowerCase();
    const match = /^data:([\w.+-]+\/[\w.+-]+);base64,([a-z\d+/]+=*)$/i.exec(String(attachment?.dataUrl || ""));
    if (!match || match[1].toLowerCase() !== type || !mediaTypes.has(type)) {
      throw new HttpError(400, "지원하지 않는 사진 또는 동영상 형식입니다.");
    }
    const data = Buffer.from(match[2], "base64");
    if (data.length === 0 || data.length > maximumAttachmentBytes) {
      throw new HttpError(413, "파일당 최대 30MB까지 첨부할 수 있습니다.");
    }
    totalBytes += data.length;
    return { name: cleanFileName(attachment.name), type, data };
  });
  if (totalBytes > maximumAttachmentBytes) throw new HttpError(413, "메시지 하나의 첨부 파일 합계는 30MB까지 가능합니다.");
  if (storedBytes + totalBytes > maximumStoredBytes) throw new HttpError(507, "시연 공간의 임시 저장 용량이 가득 찼습니다.");
  return validated;
}

function sendSse(response, event, payload) {
  response.write(`event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`);
}

function broadcast(roomCode, side, message) {
  const packet = { side, message };
  for (const subscriber of subscribers) {
    if (subscriber.session.roomCode === roomCode && canReadSide(subscriber.session, side)) {
      sendSse(subscriber.response, "message", packet);
    }
  }
}

function makeHistory(session) {
  const room = rooms.get(session.roomCode);
  if (!room) return {};
  const history = {};
  for (const side of ["victim", "suspect"]) {
    if (canReadSide(session, side)) history[side] = room.messages[side];
  }
  return history;
}

async function removeMedia(attachment) {
  const entry = mediaIndex.get(attachment.id);
  if (!entry) return;
  mediaIndex.delete(attachment.id);
  storedBytes = Math.max(0, storedBytes - entry.size);
  await unlink(entry.path).catch(() => {});
}

async function storeAttachments(attachments, roomCode, side) {
  const saved = [];
  try {
    for (const attachment of attachments) {
      const id = randomUUID();
      const extension = mediaTypes.get(attachment.type);
      const path = join(uploadDirectory, `${id}.${extension}`);
      await writeFile(path, attachment.data, { flag: "wx" });
      mediaIndex.set(id, { path, type: attachment.type, name: attachment.name, roomCode, side, size: attachment.data.length });
      storedBytes += attachment.data.length;
      saved.push({ id, name: attachment.name, type: attachment.type, url: `/api/media/${id}` });
    }
    return saved;
  } catch (error) {
    await Promise.all(saved.map(removeMedia));
    throw error;
  }
}

function trimRoom(roomCode, side) {
  const room = rooms.get(roomCode);
  if (!room) return;
  while (room.messages[side].length > maximumMessagesPerSide) {
    const removed = room.messages[side].shift();
    for (const attachment of removed.attachments || []) void removeMedia(attachment);
  }
}

function setSessionCookie(response, token) {
  const secure = production ? "; Secure" : "";
  response.setHeader("set-cookie", `court_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${sessionDurationSeconds}${secure}`);
}

function clearSessionCookie(response) {
  const secure = production ? "; Secure" : "";
  response.setHeader("set-cookie", `court_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`);
}

function setSecurityHeaders(response) {
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("referrer-policy", "same-origin");
  response.setHeader("x-frame-options", "DENY");
  response.setHeader("content-security-policy", "default-src 'self'; img-src 'self' blob:; media-src 'self' blob:; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
}

async function handleRequest(request, response) {
  setSecurityHeaders(response);
  const url = new URL(request.url || "/", "http://localhost");
  const session = sessionFromRequest(request);

  if (request.method === "GET" && url.pathname === "/api/health") {
    return json(response, 200, { ok: true });
  }

  if (request.method === "POST" && url.pathname === "/api/rooms") {
    if (rooms.size >= maximumActiveRooms) return json(response, 503, { error: "진행 중인 재판장이 가득 찼습니다." });
    const body = await readJson(request, 64 * 1024);
    let roomCode = "";
    do {
      roomCode = normalizeRoomCode(makeRoomCode());
    } while (!roomCode || rooms.has(roomCode));
    rooms.set(roomCode, createRoomState());
    const payload = createSession("judge", body.name, roomCode);
    setSessionCookie(response, signSession(payload));
    return json(response, 201, {
      role: payload.role,
      name: payload.name,
      sessionId: payload.sessionId,
      roomCode: formatRoomCode(roomCode)
    });
  }

  if (request.method === "POST" && url.pathname === "/api/join") {
    const address = clientAddress(request);
    if ((loginFailures.get(address) || []).filter((time) => Date.now() - time < 60_000).length >= 8) {
      return json(response, 429, { error: "재판장 코드 확인 횟수가 많습니다. 잠시 후 다시 시도해 주세요." });
    }
    const body = await readJson(request, 64 * 1024);
    const role = body.role;
    const roomCode = normalizeRoomCode(body.roomCode);
    if (!Object.hasOwn(roleSides, role) || !roomCode || !rooms.has(roomCode)) {
      recordLoginFailure(address);
      return json(response, 401, { error: "재판장 입장 코드가 맞지 않거나 이미 종료되었습니다." });
    }
    loginFailures.delete(address);
    const payload = createSession(role, body.name, roomCode);
    setSessionCookie(response, signSession(payload));
    return json(response, 200, {
      role: payload.role,
      name: payload.name,
      sessionId: payload.sessionId,
      roomCode: formatRoomCode(roomCode)
    });
  }

  if (request.method === "GET" && url.pathname === "/api/session") {
    if (!session) return json(response, 401, { error: "활성화된 재판장 입장이 없습니다." });
    return json(response, 200, {
      role: session.role,
      name: session.name,
      sessionId: session.sessionId,
      roomCode: formatRoomCode(session.roomCode)
    });
  }

  if (request.method === "POST" && url.pathname === "/api/logout") {
    clearSessionCookie(response);
    return json(response, 200, { ok: true });
  }

  if (request.method === "GET" && url.pathname === "/api/events") {
    if (!session) return json(response, 401, { error: "재판장에 먼저 입장해 주세요." });
    response.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      "connection": "keep-alive",
      "x-accel-buffering": "no"
    });
    response.write(": connected\n\n");
    const subscriber = { response, session };
    subscribers.add(subscriber);
    sendSse(response, "history", makeHistory(session));
    response.on("close", () => subscribers.delete(subscriber));
    return;
  }

  if (request.method === "POST" && url.pathname === "/api/messages") {
    if (!session) return json(response, 401, { error: "입장 시간이 만료되었습니다. 다시 입장해 주세요." });
    if (!allowMessageRate(session)) return json(response, 429, { error: "메시지를 잠시 쉬었다가 다시 보내 주세요." });
    const body = await readJson(request);
    const side = body.side;
    if (side !== "victim" && side !== "suspect") {
      return json(response, 400, { error: "대화방을 선택해 주세요." });
    }
    const room = rooms.get(session.roomCode);
    if (!room || !canReadSide(session, side) || !room.messages[side]) {
      return json(response, 403, { error: "대화방을 찾을 수 없습니다." });
    }
    if (!canSendSide(session, side)) {
      return json(response, 403, { error: "자신의 측 대화방에만 메시지를 보낼 수 있습니다." });
    }
    const text = String(body.text || "").trim().slice(0, 2000);
    const attachments = validateAttachments(body.attachments || []);
    if (!text && attachments.length === 0) return json(response, 400, { error: "메시지나 첨부 파일을 입력해 주세요." });
    const storedAttachments = await storeAttachments(attachments, session.roomCode, side);
    const message = {
      id: randomUUID(),
      side,
      role: session.role,
      name: session.name,
      text,
      createdAt: new Date().toISOString(),
      attachments: storedAttachments,
      senderSession: session.sessionId
    };
    room.messages[side].push(message);
    trimRoom(session.roomCode, side);
    broadcast(session.roomCode, side, message);
    return json(response, 201, { message });
  }

  if (request.method === "GET" && url.pathname.startsWith("/api/media/")) {
    if (!session) return json(response, 401, { error: "로그인이 필요합니다." });
    const id = url.pathname.slice("/api/media/".length);
    const media = mediaIndex.get(id);
    if (!media || media.roomCode !== session.roomCode || !canReadSide(session, media.side)) {
      return json(response, 404, { error: "파일을 찾을 수 없습니다." });
    }
    const fileInfo = await stat(media.path).catch(() => null);
    if (!fileInfo?.isFile()) return json(response, 404, { error: "파일을 찾을 수 없습니다." });
    response.writeHead(200, {
      "content-type": media.type,
      "content-length": fileInfo.size,
      "cache-control": "private, max-age=60",
      "content-disposition": "inline"
    });
    createReadStream(media.path).pipe(response);
    return;
  }

  if (request.method === "GET" && assets.has(url.pathname)) {
    const asset = assets.get(url.pathname);
    const filePath = join(projectRoot, asset.file);
    response.writeHead(200, { "content-type": asset.type, "cache-control": "no-cache" });
    createReadStream(filePath).pipe(response);
    return;
  }

  return json(response, 404, { error: "페이지를 찾을 수 없습니다." });
}

await rm(uploadDirectory, { recursive: true, force: true });
await mkdir(uploadDirectory, { recursive: true });

const server = createServer((request, response) => {
  void handleRequest(request, response).catch((error) => {
    if (response.headersSent) {
      response.destroy(error);
      return;
    }
    const status = error instanceof HttpError ? error.status : 500;
    if (status === 500) console.error(error);
    json(response, status, { error: error instanceof HttpError ? error.message : "서버에서 요청을 처리하지 못했습니다." });
  });
});

const heartbeat = setInterval(() => {
  for (const subscriber of subscribers) subscriber.response.write(": keepalive\n\n");
}, 20_000);
heartbeat.unref();

server.listen(port, "0.0.0.0", () => {
  console.log(`Online Courtroom is running on port ${port}.`);
  if (!production) console.log("A new room code is generated for each judge room.");
});

function shutdown() {
  clearInterval(heartbeat);
  for (const subscriber of subscribers) subscriber.response.end();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5_000).unref();
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
