"use strict";

const API_BASE_URL = String(document.querySelector('meta[name="api-base-url"]')?.content || "").trim().replace(/\/+$/, "");
const STORAGE_KEYS = { selections: "clutterless.selections.v1" };
const state = {
  files: [],
  groups: [],
  history: [],
  quarantine: [],
  selectedIds: new Set(readStored(STORAGE_KEYS.selections, [])),
  category: "all",
  query: "",
  dashboardStats: null,
};
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const elements = {
  sidebar: $("#sidebar"),
  scrim: $("#mobile-scrim"),
  views: $$(".view"),
  breadcrumb: $("#breadcrumb-current"),
  scanForm: $("#scan-form"),
  path: $("#folder-path"),
  scanSubmit: $("#scan-submit"),
  scanProgress: $("#scan-progress"),
  scanMessage: $("#scan-message"),
  scanSummary: $("#scan-summary"),
  duplicateList: $("#duplicate-list"),
  cleanupDialog: $("#confirm-dialog")
};

const CATEGORY_EXTENSIONS = {
  images: new Set(["jpg", "jpeg", "png", "gif", "webp", "bmp", "svg", "tif", "tiff", "heic", "raw"]),
  documents: new Set(["pdf", "doc", "docx", "txt", "rtf", "odt", "xls", "xlsx", "ppt", "pptx", "csv", "md"]),
  videos: new Set(["mp4", "mov", "mkv", "avi", "webm", "m4v", "wmv"]),
  audio: new Set(["mp3", "wav", "aac", "flac", "m4a", "ogg", "wma"])
};
const CATEGORY_ICONS = { images: "▧", documents: "▤", videos: "▷", audio: "♫", other: "▱" };

async function apiRequest(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers: {
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...options.headers
      }
    });
  } catch (error) {
    throw new Error(`Cannot reach the Flask backend at ${API_BASE_URL || location.origin}. Start the server and try again.`);
  }
  let result;
  try {
    result = await response.json();
  } catch (error) {
    throw new Error(`The backend returned an invalid response (${response.status}).`);
  }
  if (!response.ok) {
    const message = result.error || result.message || `Backend request failed (${response.status}).`;
    const detail = result.failed?.map((item) => item.error).filter(Boolean).join(" ");
    throw new Error(detail ? `${message} ${detail}` : message);
  }
  return result;
}

function readStored(key, fallback) {
  try {
    const value = JSON.parse(localStorage.getItem(key));
    return value === null ? fallback : value;
  } catch (error) {
    console.warn(`Could not read ${key} from local storage.`, error);
    return fallback;
  }
}

function persist(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (error) {
    showToast("Your browser could not save this update. It will be lost when you close this tab.", "error");
    console.error(`Could not save ${key} to local storage.`, error);
  }
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const power = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / (1024 ** power);
  return `${value.toFixed(power === 0 || value >= 100 ? 0 : 1)} ${units[power]}`;
}

function formatDate(value, includeTime = false) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(undefined, includeTime
    ? { dateStyle: "medium", timeStyle: "short" }
    : { dateStyle: "medium" }).format(date);
}

function fileCategory(name) {
  const extension = name.split(".").pop().toLowerCase();
  for (const [category, extensions] of Object.entries(CATEGORY_EXTENSIONS)) {
    if (extensions.has(extension)) return category;
  }
  return "other";
}

function currentStats() {
  const duplicateFiles = state.groups.reduce((total, group) => total + group.fileIds.length - 1, 0);
  const recoverable = state.groups.reduce((total, group) => {
    const protectedId = group.protectedId;
    return total + group.fileIds.reduce((sum, id) => {
      const file = state.files.find((candidate) => candidate.id === id);
      return sum + (file && id !== protectedId ? file.size : 0);
    }, 0);
  }, 0);
  const selectedSize = state.files.reduce((sum, file) => sum + (state.selectedIds.has(file.id) ? file.size : 0), 0);
  return { duplicateFiles, groupCount: state.groups.length, recoverable, selectedSize };
}

function showToast(message, type = "success") {
  const toast = document.createElement("div");
  toast.className = `toast${type === "error" ? " error" : ""}`;
  toast.textContent = message;
  $("#toast-region").append(toast);
  window.setTimeout(() => toast.remove(), 4200);
}

function setView(viewName) {
  const title = ({ dashboard: "Dashboard", scan: "Scan folder", duplicates: "Duplicate files", cleanup: "Cleanup", quarantine: "Quarantine", history: "Scan history" })[viewName];
  if (!title) return;
  elements.views.forEach((view) => view.classList.toggle("active", view.id === `view-${viewName}`));
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === viewName));
  elements.breadcrumb.textContent = title;
  elements.sidebar.classList.remove("open");
  elements.scrim.classList.remove("visible");
  if (viewName === "cleanup") renderCleanup();
  if (viewName === "duplicates") renderDuplicates();
  if (viewName === "quarantine") renderQuarantine();
  if (viewName === "history") renderHistory();
}

function setProgress(percent, title, detail) {
  $("#progress-fill").style.width = `${Math.max(0, Math.min(percent, 100))}%`;
  $("#progress-percent").textContent = `${Math.round(percent)}%`;
  $("#progress-title").textContent = title;
  $("#progress-detail").textContent = detail;
}

function showScanMessage(message, type) {
  elements.scanMessage.textContent = message;
  elements.scanMessage.className = `scan-message ${type}`;
}

function normalizeApiFile(file, index) {
  const name = String(file.name || file.path?.split(/[\\/]/).pop() || "Unnamed file");
  return {
    id: String(file.id || `api-file-${index}-${file.sha256}`),
    name,
    type: CATEGORY_EXTENSIONS[file.category] ? file.category : fileCategory(name),
    size: Number(file.size) || 0,
    path: String(file.path || file.location || ""),
    modified: new Date(file.modifiedAt || file.lastModified || 0).getTime() || 0,
    hash: String(file.sha256 || file.hash || ""),
    protected: Boolean(file.protected),
    source: "api"
  };
}

function buildGroups(files) {
  const byHash = new Map();
  for (const file of files) {
    if (!file.hash) continue;
    if (!byHash.has(file.hash)) byHash.set(file.hash, []);
    byHash.get(file.hash).push(file);
  }
  return [...byHash.entries()]
    .filter(([, matches]) => matches.length > 1)
    .map(([hash, matches], index) => {
      const ordered = [...matches].sort((a, b) => a.modified - b.modified || a.name.localeCompare(b.name));
      const protectedFile = ordered.find((file) => file.protected) || ordered[0];
      return {
        id: `group-${index}-${hash.slice(0, 10)}`,
        hash,
        fileIds: ordered.map((file) => file.id),
        protectedId: protectedFile.id
      };
    });
}

function updateSelectionDefaults(groups) {
  state.selectedIds = new Set(groups.flatMap((group) => group.fileIds.filter((id) => id !== group.protectedId)));
  persist(STORAGE_KEYS.selections, [...state.selectedIds]);
}

async function scanPathWithAPI(path) {
  elements.scanMessage.classList.add("hidden");
  elements.scanSummary.classList.add("hidden");
  elements.scanProgress.classList.remove("hidden");
  elements.scanSubmit.setAttribute("aria-busy", "true");
  elements.scanSubmit.disabled = true;
  setProgress(20, "Scanning folder on Flask…", "Validating the path and reading file contents");
  try {
    const result = await apiRequest("/api/scan", {
      method: "POST",
      body: JSON.stringify({ path })
    });
    if (!Array.isArray(result.files)) throw new Error("The scan service response must include a files array.");
    setProgress(75, "Loading saved scan results…", `${result.files_scanned} files scanned`);
    const normalized = result.files.map(normalizeApiFile);
    state.files = normalized;
    state.groups = buildGroups(normalized);
    updateSelectionDefaults(state.groups);
    await loadBackendData({ notifyError: false });
    setProgress(100, "Scan complete", `${normalized.length} files checked`);
    const skipped = result.skipped_files || 0;
    const duplicateMessage = result.duplicate_files_found
      ? `${result.duplicate_files_found} duplicate copies in ${result.duplicate_groups} groups.`
      : "No duplicate files were found.";
    showScanMessage(
      `Scan complete. ${formatNumber(normalized.length)} files scanned. ${duplicateMessage}${skipped ? ` ${skipped} inaccessible or changing files were skipped.` : ""}`,
      "success"
    );
    elements.scanSummary.innerHTML = `<strong>✓ Your scan is saved</strong><span>${formatNumber(normalized.length)} files scanned · ${formatNumber(result.duplicate_files_found)} duplicate copies · ${formatBytes(result.recoverable_bytes)} recoverable</span>`;
    elements.scanSummary.classList.remove("hidden");
  } catch (error) {
    showScanMessage(error.message, "error");
    elements.scanProgress.classList.add("hidden");
  } finally {
    elements.scanSubmit.removeAttribute("aria-busy");
    elements.scanSubmit.disabled = false;
  }
}

function formatNumber(number) {
  return new Intl.NumberFormat().format(number || 0);
}

function renderDashboard() {
  const stats = currentStats();
  const dashboardStats = state.dashboardStats;
  const fileCount = dashboardStats?.total_files_scanned;
  const duplicateCount = dashboardStats?.duplicate_files_found;
  const groupCount = dashboardStats?.duplicate_groups;
  const totalSize = dashboardStats?.total_size_bytes;
  const recoverable = dashboardStats?.recoverable_bytes;
  $("#stat-files").textContent = dashboardStats ? formatNumber(fileCount) : "—";
  $("#stat-duplicates").textContent = dashboardStats ? formatNumber(duplicateCount) : "—";
  $("#stat-groups").textContent = dashboardStats ? formatNumber(groupCount) : "—";
  $("#stat-space").textContent = dashboardStats ? formatBytes(recoverable) : "—";
  $("#stat-files-foot").textContent = dashboardStats ? "In the latest saved scan" : "Waiting for backend data";
  $("#stat-duplicates-foot").textContent = dashboardStats ? "Extra copies found" : "Connect to Flask to load results";
  $("#stat-space-foot").textContent = dashboardStats ? "From verified duplicate copies" : "Connect to Flask to load results";
  $("#nav-duplicate-count").textContent = dashboardStats ? formatNumber(duplicateCount) : "—";
  $("#nav-selected-count").textContent = formatNumber(state.selectedIds.size);
  $("#nav-quarantine-count").textContent = formatNumber(state.quarantine.length);

  const rate = totalSize ? Math.min((recoverable / totalSize) * 100, 100) : 0;
  $("#storage-percent").textContent = dashboardStats ? `${Math.round(rate)}%` : "—";
  $("#storage-recoverable").textContent = dashboardStats ? formatBytes(recoverable) : "—";
  $("#storage-other").textContent = dashboardStats ? formatBytes(Math.max(totalSize - recoverable, 0)) : "—";
  $("#storage-total").textContent = dashboardStats ? formatBytes(totalSize) : "—";
  $("#storage-note").textContent = dashboardStats ? "Based on the latest saved scan." : "Connect to Flask to load storage data.";
  $("#storage-bar-fill").style.width = `${rate}%`;
  $("#storage-donut").style.background = `conic-gradient(#796ce9 ${rate * 3.6}deg,#efeff5 ${rate * 3.6}deg 360deg)`;
  const recent = state.history.slice(0, 3);
  $("#recent-scans").innerHTML = recent.length ? recent.map((scan) => `
    <div class="recent-item"><span class="folder-icon">▰</span><div class="recent-info"><strong>${escapeHTML(scan.folder)}</strong><small>${formatDate(scan.date, true)} · ${formatNumber(scan.fileCount)} files</small></div><div class="recent-result">${formatNumber(scan.duplicateCount)} copies<small>${formatBytes(scan.recoverable)} recoverable</small></div></div>`).join("")
    : `<div class="empty-state compact-empty"><span class="empty-icon">◷</span><h3>No scan activity yet</h3><p>Scan a folder to see activity here.</p></div>`;
}

function renderDuplicates() {
  const matchingGroups = state.groups.map((group) => ({
    ...group,
    files: group.fileIds.map((id) => state.files.find((file) => file.id === id)).filter(Boolean)
  })).filter((group) => {
    const categoryMatches = state.category === "all" || group.files.some((file) => file.type === state.category);
    const queryMatches = !state.query || group.files.some((file) => file.name.toLowerCase().includes(state.query.toLowerCase()));
    return categoryMatches && queryMatches;
  });
  $("#duplicate-result-count").textContent = `${matchingGroups.length} ${matchingGroups.length === 1 ? "group" : "groups"}`;
  if (!matchingGroups.length) {
    const hasScan = Boolean(state.dashboardStats);
    const hasDuplicates = state.groups.length > 0;
    const title = hasDuplicates ? "No matching duplicates" : hasScan ? "No duplicate files found" : "No scan results yet";
    const description = hasDuplicates
      ? "Try another search or file type filter."
      : hasScan
        ? "The latest saved scan contains no duplicate files."
        : "Scan a permitted folder to find files with identical contents.";
    elements.duplicateList.innerHTML = `<div class="panel empty-state"><span class="empty-icon">⧉</span><h3>${title}</h3><p>${description}</p>${hasScan ? "" : '<button class="button button-secondary" data-go="scan">Scan a folder</button>'}</div>`;
    return;
  }
  elements.duplicateList.innerHTML = matchingGroups.map((group) => {
    const first = group.files[0];
    const copies = group.files.filter((file) => file.id !== group.protectedId);
    const groupSavings = copies.reduce((sum, file) => sum + file.size, 0);
    return `<article class="duplicate-group">
      <div class="group-heading"><span class="group-file-icon">${CATEGORY_ICONS[first.type] || CATEGORY_ICONS.other}</span><div class="group-heading-main"><strong>${escapeHTML(first.name)}</strong><small>${group.files.length} identical files · ${formatBytes(first.size)} each</small></div><span class="group-saving">${formatBytes(groupSavings)} extra</span><details class="hash-details"><summary>SHA-256</summary><code class="hash-value">${escapeHTML(group.hash)}</code></details></div>
      ${group.files.map((file) => {
        const protectedFile = file.id === group.protectedId;
        return `<div class="file-row${protectedFile ? " protected" : ""}">
          <input class="file-select" type="checkbox" data-file-id="${escapeHTML(file.id)}" aria-label="Select ${escapeHTML(file.name)}" ${protectedFile ? "disabled" : ""} ${!protectedFile && state.selectedIds.has(file.id) ? "checked" : ""}>
          <div class="file-name-cell"><span class="file-name" title="${escapeHTML(file.name)}">${escapeHTML(file.name)}</span><span class="file-location" title="${escapeHTML(file.path)}">${escapeHTML(file.path)}</span></div>
          <span class="file-meta file-type">${escapeHTML(file.type)}</span><span class="file-meta file-size">${formatBytes(file.size)}</span><span class="file-meta file-date">${formatDate(file.modified)}</span>
          <span class="file-status${protectedFile ? "" : " duplicate"}">${protectedFile ? '<span class="protected-lock">♙</span>Original' : "Duplicate"}</span>
        </div>`;
      }).join("")}
    </article>`;
  }).join("");
}

function renderCleanup() {
  const selected = state.files.filter((file) => state.selectedIds.has(file.id));
  const total = selected.reduce((sum, file) => sum + file.size, 0);
  $("#cleanup-count-label").textContent = `${selected.length} ${selected.length === 1 ? "file" : "files"} selected`;
  $("#cleanup-file-count").textContent = formatNumber(selected.length);
  $("#cleanup-total-space").textContent = formatBytes(total);
  $("#cleanup-explanation").textContent = selected.length
    ? "Selected duplicate copies will be moved by Flask into quarantine. You can restore them later."
    : "Select duplicate copies from the Duplicate files page to review cleanup.";
  $("#cleanup-button").disabled = selected.length === 0;
  $("#cleanup-file-list").innerHTML = selected.length ? selected.map((file) => `
    <div class="cleanup-file-row"><span class="group-file-icon">${CATEGORY_ICONS[file.type] || CATEGORY_ICONS.other}</span><div><strong>${escapeHTML(file.name)}</strong><small>${escapeHTML(file.path)} · ${formatBytes(file.size)}</small></div><button class="remove-file" data-remove-file="${escapeHTML(file.id)}" aria-label="Remove ${escapeHTML(file.name)} from selection">×</button></div>`).join("")
    : `<div class="cleanup-empty">${state.files.length ? "No duplicate copies selected. Select files from Duplicate files to review cleanup." : "Scan a folder to select duplicate files for cleanup."}</div>`;
}

function renderQuarantine() {
  $("#quarantine-counter").textContent = `${state.quarantine.length} ${state.quarantine.length === 1 ? "file" : "files"}`;
  $("#quarantine-description").textContent = state.quarantine.length ? `${state.quarantine.length} file${state.quarantine.length === 1 ? "" : "s"} moved to quarantine` : "No files in quarantine";
  $("#quarantine-empty").classList.toggle("hidden", state.quarantine.length > 0);
  $("#quarantine-table-body").innerHTML = state.quarantine.map((file) => `
    <tr><td><strong>${escapeHTML(file.name)}</strong><small>${formatBytes(file.size)}</small></td><td title="${escapeHTML(file.originalPath)}">${escapeHTML(file.originalPath)}</td><td title="${escapeHTML(file.quarantinePath)}">${escapeHTML(file.quarantinePath)}</td><td><span class="table-status">${escapeHTML(file.status || "Quarantined")}</span></td><td><button class="restore-button" data-restore-id="${escapeHTML(file.id)}">Restore</button></td></tr>`).join("");
}

function renderHistory() {
  $("#history-empty").classList.toggle("hidden", state.history.length > 0);
  $("#history-table-body").innerHTML = state.history.map((scan) => `
    <tr><td>${formatDate(scan.date, true)}</td><td title="${escapeHTML(scan.folder)}">${escapeHTML(scan.folder)}</td><td>${formatNumber(scan.fileCount)}</td><td>${formatNumber(scan.duplicateCount)}</td><td>${formatBytes(scan.recoverable)}</td><td>${scan.status === "completed" ? `<button class="history-open" data-open-scan="${escapeHTML(scan.id)}">View results</button>` : `<span class="table-status">${escapeHTML(scan.status || "Unavailable")}</span>`}</td></tr>`).join("");
}

function renderAll() {
  renderDashboard();
  renderDuplicates();
  renderCleanup();
  renderQuarantine();
  renderHistory();
}

function removeFromSelection(id) {
  state.selectedIds.delete(id);
  persist(STORAGE_KEYS.selections, [...state.selectedIds]);
  renderAll();
}

async function requestQuarantine(selectedFiles) {
  return apiRequest("/api/cleanup", {
    method: "POST",
    body: JSON.stringify({ file_ids: selectedFiles.map((file) => file.id) })
  });
}

function showConfirmation() {
  const selected = state.files.filter((file) => state.selectedIds.has(file.id));
  if (!selected.length) return;
  const size = selected.reduce((sum, file) => sum + file.size, 0);
  $("#confirm-description").textContent = `${selected.length} ${selected.length === 1 ? "file" : "files"} (${formatBytes(size)}) will be moved to quarantine. Originals in each duplicate group are protected.`;
  if (typeof elements.cleanupDialog.showModal === "function") elements.cleanupDialog.showModal();
  else if (window.confirm($("#confirm-description").textContent)) performCleanup();
}

async function performCleanup() {
  const selected = state.files.filter((file) => state.selectedIds.has(file.id));
  if (!selected.length) return;
  $("#confirm-cleanup").disabled = true;
  try {
    const result = await requestQuarantine(selected);
    const movedIds = new Set((result.files || []).map((file) => String(file.id)));
    if (!movedIds.size) {
      const failures = (result.failed || []).map((item) => item.error).filter(Boolean);
      throw new Error(failures.join(" ") || "The backend did not confirm moving any selected files.");
    }
    state.selectedIds = new Set([...state.selectedIds].filter((id) => !movedIds.has(id)));
    persist(STORAGE_KEYS.selections, [...state.selectedIds]);
    await loadBackendData({ notifyError: false });
    elements.cleanupDialog.close();
    const failures = (result.failed || []).map((item) => item.error).filter(Boolean);
    showToast(`${movedIds.size} files moved to quarantine.${failures.length ? ` Not moved: ${failures.join(" ")}` : ""}`);
    setView("quarantine");
  } catch (error) {
    showToast(`${error.message} No files were moved unless the backend confirmed them.`, "error");
  } finally {
    $("#confirm-cleanup").disabled = false;
  }
}

async function restoreFile(id) {
  try {
    const result = await apiRequest("/api/restore", {
      method: "POST",
      body: JSON.stringify({ quarantine_ids: [Number(id)] })
    });
    const restored = result.restored || [];
    if (!restored.length) {
      const failures = (result.failed || []).map((item) => item.error).filter(Boolean);
      throw new Error(failures.join(" ") || "The backend did not confirm restoring this file.");
    }
    await loadBackendData({ notifyError: false });
    showToast(`${restored.length} file restored to its original location.`);
  } catch (error) {
    showToast(`${error.message} The file remains in quarantine.`, "error");
  }
}

async function loadBackendData({ notifyError = true } = {}) {
  try {
    const responses = await Promise.all([
      apiRequest("/api/dashboard"),
      apiRequest("/api/duplicates"),
      apiRequest("/api/history"),
      apiRequest("/api/quarantine")
    ]);
    const [dashboard, duplicates, history, quarantine] = responses;
    state.dashboardStats = {
      total_files_scanned: dashboard.total_files_scanned,
      duplicate_files_found: dashboard.duplicate_files_found,
      duplicate_groups: dashboard.duplicate_groups,
      recoverable_bytes: dashboard.recoverable_bytes,
      total_size_bytes: dashboard.total_size_bytes
    };
    state.files = (duplicates.files || []).map(normalizeApiFile);
    state.groups = buildGroups(state.files);
    state.history = (history.history || []).map((scan) => ({
      id: String(scan.id),
      date: scan.date,
      folder: scan.folder,
      fileCount: scan.fileCount,
      duplicateCount: scan.duplicateCount,
      groupCount: scan.groupCount,
      recoverable: scan.recoverable,
      source: "api",
      status: scan.status
    }));
    state.quarantine = (quarantine.files || []).map((file) => ({
      id: String(file.id),
      originalId: String(file.scanned_file_id),
      name: file.name,
      size: file.size,
      type: CATEGORY_EXTENSIONS[file.category] ? file.category : fileCategory(file.name),
      modified: new Date(file.modifiedAt).getTime() || 0,
      originalPath: file.originalPath,
      quarantinePath: file.quarantinePath,
      hash: file.sha256,
      status: file.status === "quarantined" ? "Quarantined" : file.status,
      source: "api"
    }));
    const selectableIds = new Set(
      state.groups.flatMap((group) => group.fileIds.filter((id) => id !== group.protectedId))
    );
    state.selectedIds = new Set([...state.selectedIds].filter((id) => selectableIds.has(String(id))));
    persist(STORAGE_KEYS.selections, [...state.selectedIds]);
    renderAll();
    return true;
  } catch (error) {
    console.error("Could not load saved backend data.", error);
    if (notifyError) showToast(error.message, "error");
    if (!notifyError) throw error;
    return false;
  }
}

async function openHistoricalScan(scan) {
  if (scan.status !== "completed") {
    throw new Error("Results are unavailable because this scan did not complete.");
  }
  const result = await apiRequest(`/api/duplicates?scan_id=${encodeURIComponent(scan.id)}`);
  state.files = (result.files || []).map(normalizeApiFile);
  state.groups = buildGroups(state.files);
  state.selectedIds = new Set(state.groups.flatMap((group) => group.fileIds.filter((id) => id !== group.protectedId)));
  state.dashboardStats = {
    total_files_scanned: scan.fileCount,
    duplicate_files_found: scan.duplicateCount,
    duplicate_groups: scan.groupCount,
    recoverable_bytes: scan.recoverable,
    total_size_bytes: state.files.reduce((sum, file) => sum + file.size, 0)
  };
  persist(STORAGE_KEYS.selections, [...state.selectedIds]);
  renderAll();
  setView("duplicates");
}

function bindEvents() {
  document.addEventListener("click", (event) => {
    const navigation = event.target.closest("[data-view], [data-go]");
    if (navigation) {
      setView(navigation.dataset.view || navigation.dataset.go);
      return;
    }
    const removeButton = event.target.closest("[data-remove-file]");
    if (removeButton) {
      removeFromSelection(removeButton.dataset.removeFile);
      return;
    }
    const restoreButton = event.target.closest("[data-restore-id]");
    if (restoreButton) {
      restoreFile(restoreButton.dataset.restoreId);
      return;
    }
    const historyButton = event.target.closest("[data-open-scan]");
    if (historyButton) {
      const entry = state.history.find((scan) => scan.id === historyButton.dataset.openScan);
      if (entry) openHistoricalScan(entry).catch((error) => showToast(error.message, "error"));
    }
  });

  elements.scanForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const path = elements.path.value.trim();
    if (path) {
      scanPathWithAPI(path);
    } else {
      showScanMessage("Enter a folder path inside a configured scan directory.", "error");
    }
  });
  $("#duplicate-search").addEventListener("input", (event) => {
    state.query = event.target.value.trim();
    renderDuplicates();
  });
  $("#category-filters").addEventListener("click", (event) => {
    const filter = event.target.closest("[data-category]");
    if (!filter) return;
    state.category = filter.dataset.category;
    $$(".filter-chip").forEach((chip) => chip.classList.toggle("active", chip === filter));
    renderDuplicates();
  });
  elements.duplicateList.addEventListener("change", (event) => {
    const checkbox = event.target.closest("[data-file-id]");
    if (!checkbox) return;
    if (checkbox.checked) state.selectedIds.add(checkbox.dataset.fileId);
    else state.selectedIds.delete(checkbox.dataset.fileId);
    persist(STORAGE_KEYS.selections, [...state.selectedIds]);
    renderDashboard();
    renderCleanup();
  });
  $("#clear-selection").addEventListener("click", () => {
    state.selectedIds.clear();
    persist(STORAGE_KEYS.selections, []);
    renderAll();
  });
  $("#cleanup-button").addEventListener("click", showConfirmation);
  $("#cancel-cleanup").addEventListener("click", () => elements.cleanupDialog.close());
  $("#confirm-cleanup").addEventListener("click", performCleanup);
  $("#help-button").addEventListener("click", () => {
    showToast("Enter a folder path inside a configured scan directory. Flask scans it and moves confirmed duplicate copies to quarantine.");
  });
  $("#mobile-menu").addEventListener("click", () => {
    elements.sidebar.classList.add("open");
    elements.scrim.classList.add("visible");
  });
  elements.scrim.addEventListener("click", () => {
    elements.sidebar.classList.remove("open");
    elements.scrim.classList.remove("visible");
  });
}

bindEvents();
renderAll();
loadBackendData();
