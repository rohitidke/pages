(() => {
  "use strict";

  const CONFIG = {
    manifestPath: "data/manifest.enc.json",
    minPatternLength: 4,
    baseDelayMs: 10000,
    maxDelayMs: 100000,
    lockTickMs: 100,
    alg: "AES-CBC+HMAC-SHA256",
  };

  const state = {
    manifestEnvelope: null,
    manifestError: null,
    failures: 0,
    lockedUntil: 0,
    lockInterval: null,
    isDrawing: false,
    activePointerId: null,
    pointerPoint: null,
    patternSequence: [],
    patternSet: new Set(),
    unlockInProgress: false,
    profileData: null,
    mediaUrls: new Map(),
    currentStoryIndex: 0,
    currentStoryMediaIndex: 0,
    currentPostIndex: 0,
    currentPostMediaIndex: 0,
  };

  const el = {};
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  document.addEventListener("DOMContentLoaded", init);

  async function init() {
    cacheElements();
    bindEvents();
    await preloadManifest();
  }

  function cacheElements() {
    el.lockScreen = document.getElementById("lock-screen");
    el.loadingScreen = document.getElementById("loading-screen");
    el.profileScreen = document.getElementById("profile-screen");

    el.patternArea = document.getElementById("pattern-area");
    el.patternPath = document.getElementById("pattern-path");
    el.patternSvg = document.getElementById("pattern-svg");
    el.patternDots = Array.from(document.querySelectorAll(".pattern-dot"));

    el.lockStatus = document.getElementById("lock-status");
    el.delayTimer = document.getElementById("delay-timer");
    el.clearPatternBtn = document.getElementById("clear-pattern");
    el.loadingText = document.getElementById("loading-text");

    el.username = document.getElementById("username");
    el.displayName = document.getElementById("display-name");
    el.bio = document.getElementById("bio");
    el.avatar = document.getElementById("avatar");

    el.storiesTrack = document.getElementById("stories-track");
    el.postsGrid = document.getElementById("posts-grid");

    el.storyModal = document.getElementById("story-modal");
    el.storyImage = document.getElementById("story-image");
    el.storyTitle = document.getElementById("story-title");
    el.storyIndex = document.getElementById("story-index");
    el.storyCaption = document.getElementById("story-caption");
    el.storyPrev = document.getElementById("story-prev");
    el.storyNext = document.getElementById("story-next");
    el.storyClose = document.getElementById("close-story");

    el.postModal = document.getElementById("post-modal");
    el.postImage = document.getElementById("post-image");
    el.postCaption = document.getElementById("post-caption");
    el.postIndex = document.getElementById("post-index");
    el.postDate = document.getElementById("post-date");
    el.postPrev = document.getElementById("post-prev");
    el.postNext = document.getElementById("post-next");
    el.postClose = document.getElementById("close-post");

    el.errorBanner = document.getElementById("error-banner");
  }

  function bindEvents() {
    el.patternDots.forEach((dot) => {
      dot.addEventListener("pointerdown", onDotPointerDown);
      dot.addEventListener("dragstart", (event) => event.preventDefault());
    });

    window.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerup", onPointerUp);
    window.addEventListener("pointercancel", onPointerUp);

    el.clearPatternBtn.addEventListener("click", () => {
      if (state.unlockInProgress || isLockedOut()) {
        return;
      }
      clearPattern();
      updateLockStatus("Pattern cleared.");
    });

    el.storyPrev.addEventListener("click", () => shiftStory(-1));
    el.storyNext.addEventListener("click", () => shiftStory(1));
    el.storyClose.addEventListener("click", closeStoryModal);
    el.postPrev.addEventListener("click", () => shiftPostMedia(-1));
    el.postNext.addEventListener("click", () => shiftPostMedia(1));
    el.postClose.addEventListener("click", closePostModal);

    document.querySelectorAll(".modal-backdrop").forEach((backdrop) => {
      backdrop.addEventListener("click", () => {
        const target = backdrop.getAttribute("data-close");
        if (target === "story") {
          closeStoryModal();
        } else if (target === "post") {
          closePostModal();
        }
      });
    });

    document.addEventListener("keydown", onKeyDown);
    window.addEventListener("beforeunload", () => revokeMediaUrls());
  }

  async function preloadManifest() {
    try {
      state.manifestEnvelope = await fetchJson(CONFIG.manifestPath);
      state.manifestError = null;
      updateLockStatus("Draw your pattern to unlock.");
    } catch (error) {
      state.manifestEnvelope = null;
      state.manifestError = error;
      updateLockStatus(
        "Encrypted profile data not found. Run: python3 tools/build_profile.py",
        "error"
      );
    }
  }

  function onDotPointerDown(event) {
    if (state.unlockInProgress || isLockedOut()) {
      return;
    }

    event.preventDefault();

    const dot = event.currentTarget;
    const index = Number(dot.dataset.index);
    if (!Number.isInteger(index)) {
      return;
    }

    state.isDrawing = true;
    state.activePointerId = event.pointerId;
    state.pointerPoint = toPatternPoint(event.clientX, event.clientY);
    clearPattern();
    addDot(index);
    renderPatternPath();

    try {
      dot.setPointerCapture(event.pointerId);
    } catch (_error) {
      // Pointer capture can fail on some browsers; drawing still works without it.
    }
  }

  function onPointerMove(event) {
    if (!state.isDrawing || event.pointerId !== state.activePointerId) {
      return;
    }

    state.pointerPoint = toPatternPoint(event.clientX, event.clientY);

    const hoverDot = getDotAtClientPoint(event.clientX, event.clientY);
    if (hoverDot) {
      addDot(Number(hoverDot.dataset.index));
    }

    renderPatternPath();
  }

  function onPointerUp(event) {
    if (!state.isDrawing || event.pointerId !== state.activePointerId) {
      return;
    }

    state.isDrawing = false;
    state.activePointerId = null;
    state.pointerPoint = null;
    renderPatternPath();

    if (state.patternSequence.length < CONFIG.minPatternLength) {
      updateLockStatus(
        `Pattern must include at least ${CONFIG.minPatternLength} dots.`,
        "error"
      );
      setTimeout(clearPattern, 150);
      return;
    }

    const pattern = state.patternSequence.join("-");
    void attemptUnlock(pattern);
  }

  function addDot(index) {
    if (!Number.isInteger(index) || index < 1 || index > 9 || state.patternSet.has(index)) {
      return;
    }

    const previous = state.patternSequence[state.patternSequence.length - 1];
    if (previous) {
      const middle = getIntermediateDot(previous, index);
      if (middle && !state.patternSet.has(middle)) {
        pushDot(middle);
      }
    }

    pushDot(index);
  }

  function pushDot(index) {
    state.patternSequence.push(index);
    state.patternSet.add(index);
    const dot = el.patternDots.find((entry) => Number(entry.dataset.index) === index);
    if (dot) {
      dot.classList.add("selected");
    }
  }

  function getIntermediateDot(fromIndex, toIndex) {
    const from = indexToCoord(fromIndex);
    const to = indexToCoord(toIndex);
    if (!from || !to) {
      return null;
    }

    const dRow = to.row - from.row;
    const dCol = to.col - from.col;
    const hasMiddle =
      (Math.abs(dRow) === 2 && dCol === 0) ||
      (Math.abs(dCol) === 2 && dRow === 0) ||
      (Math.abs(dRow) === 2 && Math.abs(dCol) === 2);

    if (!hasMiddle) {
      return null;
    }

    const midRow = from.row + dRow / 2;
    const midCol = from.col + dCol / 2;
    return coordToIndex(midRow, midCol);
  }

  function indexToCoord(index) {
    const i = index - 1;
    if (i < 0 || i > 8) {
      return null;
    }
    return {
      row: Math.floor(i / 3),
      col: i % 3,
    };
  }

  function coordToIndex(row, col) {
    return row * 3 + col + 1;
  }

  function renderPatternPath() {
    const areaRect = el.patternArea.getBoundingClientRect();
    if (!areaRect.width || !areaRect.height) {
      return;
    }

    el.patternSvg.setAttribute("viewBox", `0 0 ${areaRect.width} ${areaRect.height}`);

    const points = state.patternSequence
      .map((index) => {
        const dot = el.patternDots.find((entry) => Number(entry.dataset.index) === index);
        return dot ? dotCenterInArea(dot, areaRect) : null;
      })
      .filter(Boolean);

    if (state.isDrawing && state.pointerPoint) {
      points.push(state.pointerPoint);
    }

    const polyline = points.map((point) => `${point.x},${point.y}`).join(" ");
    el.patternPath.setAttribute("points", polyline);
  }

  function dotCenterInArea(dot, areaRect) {
    const rect = dot.getBoundingClientRect();
    return {
      x: rect.left - areaRect.left + rect.width / 2,
      y: rect.top - areaRect.top + rect.height / 2,
    };
  }

  function toPatternPoint(clientX, clientY) {
    const rect = el.patternArea.getBoundingClientRect();
    return {
      x: clientX - rect.left,
      y: clientY - rect.top,
    };
  }

  function getDotAtClientPoint(clientX, clientY) {
    const hovered = document.elementFromPoint(clientX, clientY);
    if (!hovered) {
      return null;
    }
    const dot = hovered.closest(".pattern-dot");
    if (!dot || !el.patternArea.contains(dot)) {
      return null;
    }
    return dot;
  }

  function clearPattern() {
    state.patternSequence = [];
    state.patternSet.clear();
    el.patternDots.forEach((dot) => dot.classList.remove("selected"));
    el.patternPath.setAttribute("points", "");
  }

  async function attemptUnlock(pattern) {
    if (state.unlockInProgress) {
      return;
    }

    if (isLockedOut()) {
      updateLockStatus("Please wait before trying again.", "error");
      return;
    }

    state.unlockInProgress = true;
    updateLockStatus("Verifying pattern...");

    try {
      if (!state.manifestEnvelope) {
        await preloadManifest();
      }

      if (!state.manifestEnvelope) {
        throw makeError(
          "SETUP_MISSING",
          "Encrypted profile manifest is unavailable. Run the build script first."
        );
      }

      const manifestBytes = await decryptEnvelope(state.manifestEnvelope, pattern);
      const manifest = decodeManifest(manifestBytes);

      showScreen("loading");
      el.loadingText.textContent = "Decrypting media...";

      revokeMediaUrls();
      const mediaMap = await decryptMediaFiles(manifest, pattern);
      attachMediaSources(manifest, mediaMap);

      state.profileData = manifest;
      state.mediaUrls = mediaMap;
      state.failures = 0;
      state.lockedUntil = 0;
      refreshLockDelayUI();

      renderProfile(manifest);
      updateLockStatus("Unlocked.", "success");
      showScreen("profile");
    } catch (error) {
      showScreen("lock");
      clearPattern();

      if (error.code === "SETUP_MISSING" || error.code === "SETUP_INVALID") {
        updateLockStatus(error.message, "error");
        showError(error.message);
      } else {
        applyLockDelay();
        updateLockStatus("Pattern is incorrect or data was tampered.", "error");
      }
    } finally {
      state.unlockInProgress = false;
    }
  }

  function decodeManifest(plainBytes) {
    try {
      const manifest = JSON.parse(decoder.decode(plainBytes));
      validateManifestShape(manifest);
      return manifest;
    } catch (_error) {
      throw makeError("SETUP_INVALID", "Manifest payload is invalid JSON.");
    }
  }

  function validateManifestShape(manifest) {
    if (!manifest || typeof manifest !== "object") {
      throw makeError("SETUP_INVALID", "Manifest object is malformed.");
    }

    if (!manifest.profile || typeof manifest.profile !== "object") {
      throw makeError("SETUP_INVALID", "Manifest profile block is missing.");
    }

    if (!Array.isArray(manifest.stories) || !Array.isArray(manifest.posts)) {
      throw makeError("SETUP_INVALID", "Manifest stories/posts must be arrays.");
    }

    const avatar = manifest.profile.avatar;
    if (!isMediaRef(avatar)) {
      throw makeError("SETUP_INVALID", "Manifest avatar media is missing.");
    }

    manifest.stories.forEach((story, index) => {
      if (!story || typeof story !== "object") {
        throw makeError("SETUP_INVALID", `Story ${index + 1} is malformed.`);
      }
      const items = normalizeMediaItems(story);
      if (!items.length) {
        throw makeError("SETUP_INVALID", `Story ${index + 1} has no media.`);
      }
    });

    manifest.posts.forEach((post, index) => {
      if (!post || typeof post !== "object") {
        throw makeError("SETUP_INVALID", `Post ${index + 1} is malformed.`);
      }
      const items = normalizeMediaItems(post);
      if (!items.length) {
        throw makeError("SETUP_INVALID", `Post ${index + 1} has no media.`);
      }
    });
  }

  async function decryptMediaFiles(manifest, pattern) {
    const refs = collectMediaRefs(manifest);
    const map = new Map();

    for (const ref of refs) {
      if (map.has(ref.file)) {
        continue;
      }

      const envelope = await fetchJson(ref.file);
      const bytes = await decryptEnvelope(envelope, pattern);
      const mime = typeof ref.mime === "string" ? ref.mime : "application/octet-stream";
      const url = URL.createObjectURL(new Blob([bytes], { type: mime }));
      map.set(ref.file, url);
    }

    return map;
  }

  function collectMediaRefs(manifest) {
    const refs = [];

    refs.push(manifest.profile.avatar);

    manifest.stories.forEach((story) => {
      refs.push(...normalizeMediaItems(story));
    });

    manifest.posts.forEach((post) => {
      refs.push(...normalizeMediaItems(post));
    });

    return refs;
  }

  function attachMediaSources(manifest, mediaMap) {
    manifest.profile.avatar.src = mediaMap.get(manifest.profile.avatar.file) || "";

    manifest.stories.forEach((story) => {
      const items = normalizeMediaItems(story);
      items.forEach((item) => {
        item.src = mediaMap.get(item.file) || "";
      });
      story.mediaItems = items;
      story.media = items[0];
    });

    manifest.posts.forEach((post) => {
      const items = normalizeMediaItems(post);
      items.forEach((item) => {
        item.src = mediaMap.get(item.file) || "";
      });
      post.mediaItems = items;
      post.media = items[0];
    });
  }

  function normalizeMediaItems(entity) {
    if (!entity || typeof entity !== "object") {
      return [];
    }

    const refs = [];
    if (Array.isArray(entity.mediaItems)) {
      entity.mediaItems.forEach((entry) => {
        if (isMediaRef(entry)) {
          refs.push(entry);
        }
      });
    }

    if (!refs.length && isMediaRef(entity.media)) {
      refs.push(entity.media);
    }

    return refs;
  }

  function isMediaRef(value) {
    return Boolean(value && typeof value === "object" && typeof value.file === "string");
  }

  function renderProfile(manifest) {
    const username = String(manifest.profile.username || "username").replace(/^@/, "");
    el.username.textContent = `@${username}`;
    el.displayName.textContent = String(manifest.profile.displayName || "Display Name");
    el.bio.textContent = String(manifest.profile.bio || "");
    el.avatar.src = manifest.profile.avatar.src;

    renderStories(manifest.stories || []);
    renderPosts(manifest.posts || []);
  }

  function renderStories(stories) {
    el.storiesTrack.innerHTML = "";

    if (!stories.length) {
      const empty = document.createElement("p");
      empty.className = "subtitle";
      empty.textContent = "No stories yet.";
      el.storiesTrack.appendChild(empty);
      return;
    }

    stories.forEach((story, index) => {
      const mediaItems = normalizeMediaItems(story);
      const cover = mediaItems[0];
      if (!cover || !cover.src) {
        return;
      }

      const button = document.createElement("button");
      button.className = "story-chip";
      button.type = "button";
      button.setAttribute("aria-label", `Open story ${story.title || index + 1}`);

      const wrap = document.createElement("span");
      wrap.className = "story-thumb-wrap";
      const img = document.createElement("img");
      img.className = "story-thumb";
      img.src = cover.src;
      img.alt = story.title || "Story";
      wrap.appendChild(img);

      const label = document.createElement("span");
      label.textContent = story.title || "Story";

      button.appendChild(wrap);
      button.appendChild(label);
      button.addEventListener("click", () => openStoryModal(index));
      el.storiesTrack.appendChild(button);
    });
  }

  function renderPosts(posts) {
    el.postsGrid.innerHTML = "";

    if (!posts.length) {
      const empty = document.createElement("p");
      empty.className = "subtitle";
      empty.textContent = "No posts yet.";
      el.postsGrid.appendChild(empty);
      return;
    }

    posts.forEach((post, index) => {
      const mediaItems = normalizeMediaItems(post);
      const cover = mediaItems[0];
      if (!cover || !cover.src) {
        return;
      }

      const button = document.createElement("button");
      button.className = "post-tile";
      button.type = "button";
      button.setAttribute("aria-label", `Open post ${index + 1}`);

      const img = document.createElement("img");
      img.src = cover.src;
      img.alt = post.caption || `Post ${index + 1}`;

      button.appendChild(img);
      button.addEventListener("click", () => openPostModal(index));
      el.postsGrid.appendChild(button);
    });
  }

  function openStoryModal(index) {
    if (!state.profileData || !state.profileData.stories.length) {
      return;
    }
    state.currentStoryIndex = index;
    state.currentStoryMediaIndex = 0;
    renderStorySlide();
    el.storyModal.classList.remove("hidden");
    el.storyModal.setAttribute("aria-hidden", "false");
  }

  function renderStorySlide() {
    const stories = state.profileData.stories;
    const story = stories[state.currentStoryIndex];
    if (!story) {
      return;
    }

    const mediaItems = normalizeMediaItems(story);
    if (!mediaItems.length) {
      return;
    }

    const safeMediaIndex = clampIndex(state.currentStoryMediaIndex, mediaItems.length);
    state.currentStoryMediaIndex = safeMediaIndex;
    const media = mediaItems[safeMediaIndex];
    const storyPosition = state.currentStoryIndex + 1;

    el.storyImage.src = media.src || "";
    el.storyImage.alt = story.title || "Story";
    el.storyTitle.textContent = story.title || "Story";
    el.storyIndex.textContent =
      `Story ${storyPosition}/${stories.length} • Photo ${safeMediaIndex + 1}/${mediaItems.length}`;
    el.storyCaption.textContent = story.caption || "";
  }

  function shiftStory(delta) {
    if (!state.profileData || !state.profileData.stories.length) {
      return;
    }

    const stories = state.profileData.stories;
    let storyIndex = state.currentStoryIndex;
    let mediaIndex = state.currentStoryMediaIndex + delta;
    let safety = 0;

    while (safety < stories.length * 2) {
      const items = normalizeMediaItems(stories[storyIndex]);
      if (!items.length) {
        storyIndex = (storyIndex + (delta >= 0 ? 1 : -1) + stories.length) % stories.length;
        mediaIndex = delta >= 0 ? 0 : -1;
        safety += 1;
        continue;
      }

      if (mediaIndex < 0) {
        storyIndex = (storyIndex - 1 + stories.length) % stories.length;
        mediaIndex = normalizeMediaItems(stories[storyIndex]).length - 1;
        safety += 1;
        continue;
      }

      if (mediaIndex >= items.length) {
        storyIndex = (storyIndex + 1) % stories.length;
        mediaIndex = 0;
        safety += 1;
        continue;
      }

      state.currentStoryIndex = storyIndex;
      state.currentStoryMediaIndex = mediaIndex;
      renderStorySlide();
      return;
    }
  }

  function closeStoryModal() {
    el.storyModal.classList.add("hidden");
    el.storyModal.setAttribute("aria-hidden", "true");
  }

  function openPostModal(index) {
    if (!state.profileData || !state.profileData.posts.length) {
      return;
    }

    state.currentPostIndex = index;
    state.currentPostMediaIndex = 0;
    renderPostSlide();

    el.postModal.classList.remove("hidden");
    el.postModal.setAttribute("aria-hidden", "false");
  }

  function renderPostSlide() {
    if (!state.profileData || !state.profileData.posts.length) {
      return;
    }

    const post = state.profileData.posts[state.currentPostIndex];
    if (!post) {
      return;
    }

    const mediaItems = normalizeMediaItems(post);
    if (!mediaItems.length) {
      return;
    }

    const safeMediaIndex = clampIndex(state.currentPostMediaIndex, mediaItems.length);
    state.currentPostMediaIndex = safeMediaIndex;
    const media = mediaItems[safeMediaIndex];

    el.postImage.src = media.src || "";
    el.postImage.alt = post.caption || "Post";
    el.postCaption.textContent = post.caption || "";
    el.postIndex.textContent = `Photo ${safeMediaIndex + 1}/${mediaItems.length}`;
    el.postDate.textContent = post.date || "";
    el.postPrev.disabled = mediaItems.length <= 1;
    el.postNext.disabled = mediaItems.length <= 1;
  }

  function shiftPostMedia(delta) {
    if (!state.profileData || !state.profileData.posts.length) {
      return;
    }
    const post = state.profileData.posts[state.currentPostIndex];
    if (!post) {
      return;
    }
    const mediaItems = normalizeMediaItems(post);
    if (mediaItems.length <= 1) {
      return;
    }

    state.currentPostMediaIndex =
      (state.currentPostMediaIndex + delta + mediaItems.length) % mediaItems.length;
    renderPostSlide();
  }

  function closePostModal() {
    el.postModal.classList.add("hidden");
    el.postModal.setAttribute("aria-hidden", "true");
  }

  function onKeyDown(event) {
    if (event.key === "Escape") {
      closeStoryModal();
      closePostModal();
      return;
    }

    if (!el.postModal.classList.contains("hidden")) {
      if (event.key === "ArrowRight") {
        shiftPostMedia(1);
      }
      if (event.key === "ArrowLeft") {
        shiftPostMedia(-1);
      }
      return;
    }

    if (!el.storyModal.classList.contains("hidden")) {
      if (event.key === "ArrowRight") {
        shiftStory(1);
      }
      if (event.key === "ArrowLeft") {
        shiftStory(-1);
      }
    }
  }

  function showScreen(target) {
    el.lockScreen.classList.toggle("hidden", target !== "lock");
    el.loadingScreen.classList.toggle("hidden", target !== "loading");
    el.profileScreen.classList.toggle("hidden", target !== "profile");
  }

  function updateLockStatus(message, tone = "default") {
    el.lockStatus.textContent = message;
    el.lockStatus.classList.remove("error", "success");
    if (tone === "error") {
      el.lockStatus.classList.add("error");
    }
    if (tone === "success") {
      el.lockStatus.classList.add("success");
    }
  }

  function applyLockDelay() {
    state.failures += 1;
    const delayMs = Math.min(
      CONFIG.maxDelayMs,
      CONFIG.baseDelayMs * 2 ** (state.failures - 1)
    );
    state.lockedUntil = Date.now() + delayMs;
    refreshLockDelayUI();
  }

  function refreshLockDelayUI() {
    if (state.lockInterval) {
      clearInterval(state.lockInterval);
      state.lockInterval = null;
    }

    if (!isLockedOut()) {
      el.delayTimer.textContent = "";
      el.clearPatternBtn.disabled = false;
      return;
    }

    el.clearPatternBtn.disabled = true;

    state.lockInterval = window.setInterval(() => {
      if (!isLockedOut()) {
        if (state.lockInterval) {
          clearInterval(state.lockInterval);
          state.lockInterval = null;
        }
        el.delayTimer.textContent = "";
        el.clearPatternBtn.disabled = false;
        updateLockStatus("You can try again.");
        return;
      }

      const remainingMs = Math.max(0, state.lockedUntil - Date.now());
      el.delayTimer.textContent = `Retry in ${(remainingMs / 1000).toFixed(1)}s`;
    }, CONFIG.lockTickMs);
  }

  function isLockedOut() {
    return Date.now() < state.lockedUntil;
  }

  function showError(message) {
    el.errorBanner.textContent = message;
    el.errorBanner.classList.remove("hidden");
    window.setTimeout(() => {
      el.errorBanner.classList.add("hidden");
    }, 5000);
  }

  function revokeMediaUrls() {
    state.mediaUrls.forEach((url) => URL.revokeObjectURL(url));
    state.mediaUrls = new Map();
  }

  async function fetchJson(path) {
    let response;
    try {
      response = await fetch(path, { cache: "no-store" });
    } catch (_error) {
      throw makeError("SETUP_MISSING", `Network error while loading ${path}`);
    }

    if (!response.ok) {
      throw makeError("SETUP_MISSING", `Missing encrypted file: ${path}`);
    }

    try {
      return await response.json();
    } catch (_error) {
      throw makeError("SETUP_INVALID", `Invalid JSON envelope at ${path}`);
    }
  }

  async function decryptEnvelope(envelope, secret) {
    validateEnvelope(envelope);

    const salt = base64ToBytes(envelope.salt);
    const iv = base64ToBytes(envelope.iv);
    const ciphertext = base64ToBytes(envelope.ciphertext);
    const mac = base64ToBytes(envelope.mac);

    const iterations = Number(envelope.iter);
    if (!Number.isInteger(iterations) || iterations <= 0) {
      throw makeError("SETUP_INVALID", "Invalid PBKDF2 iteration count.");
    }

    const keys = await deriveKeys(secret, salt, iterations);
    const macMessage = buildMacMessage(envelope.v, envelope.alg, iterations, salt, iv, ciphertext);

    const macValid = await crypto.subtle.verify("HMAC", keys.macKey, mac, macMessage);
    if (!macValid) {
      throw makeError("AUTH_FAILED", "MAC verification failed.");
    }

    try {
      const plainBuffer = await crypto.subtle.decrypt(
        { name: "AES-CBC", iv },
        keys.encKey,
        ciphertext
      );
      return new Uint8Array(plainBuffer);
    } catch (_error) {
      throw makeError("DECRYPT_FAILED", "AES decryption failed.");
    }
  }

  function validateEnvelope(envelope) {
    if (!envelope || typeof envelope !== "object") {
      throw makeError("SETUP_INVALID", "Encrypted envelope must be a JSON object.");
    }

    const required = ["v", "alg", "salt", "iv", "iter", "ciphertext", "mac"];
    const missing = required.filter((field) => !(field in envelope));
    if (missing.length) {
      throw makeError("SETUP_INVALID", `Envelope missing: ${missing.join(", ")}`);
    }

    if (envelope.v !== 1 || envelope.alg !== CONFIG.alg) {
      throw makeError("SETUP_INVALID", "Envelope algorithm/version mismatch.");
    }
  }

  async function deriveKeys(secret, salt, iterations) {
    if (!secret || typeof secret !== "string") {
      throw makeError("AUTH_FAILED", "Pattern must be a non-empty string.");
    }

    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bitBuffer = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations,
      },
      keyMaterial,
      512
    );

    const derived = new Uint8Array(bitBuffer);
    const encBytes = derived.slice(0, 32);
    const macBytes = derived.slice(32, 64);

    const encKey = await crypto.subtle.importKey(
      "raw",
      encBytes,
      { name: "AES-CBC" },
      false,
      ["decrypt"]
    );

    const macKey = await crypto.subtle.importKey(
      "raw",
      macBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    return { encKey, macKey };
  }

  function buildMacMessage(version, alg, iter, salt, iv, ciphertext) {
    const header = encoder.encode(`v=${version};alg=${alg};iter=${iter};`);

    return concatBytes([
      header,
      u32be(salt.length),
      salt,
      u32be(iv.length),
      iv,
      u32be(ciphertext.length),
      ciphertext,
    ]);
  }

  function u32be(value) {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value, false);
    return out;
  }

  function concatBytes(chunks) {
    const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;

    chunks.forEach((chunk) => {
      out.set(chunk, offset);
      offset += chunk.length;
    });

    return out;
  }

  function base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function clampIndex(index, length) {
    if (!Number.isInteger(index) || length <= 0) {
      return 0;
    }
    if (index < 0) {
      return 0;
    }
    if (index >= length) {
      return length - 1;
    }
    return index;
  }

  function makeError(code, message) {
    const error = new Error(message);
    error.code = code;
    return error;
  }
})();
