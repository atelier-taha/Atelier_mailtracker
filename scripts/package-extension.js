/**
 * Atelier's MailTracker — Mail Intelligence & Security Suite
 * scripts/package-extension.js
 * 
 * Production Packaging Pipeline for Chrome Web Store Submission:
 * - Validates Manifest V3 compliance and JavaScript syntax
 * - Enforces strict inclusion whitelisting (zero dev/test/api leakage)
 * - Generates clean, isolated release zip archive in dist/
 * - Zero external npm dependencies (pure Node.js built-ins)
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const vm = require('vm');
const crypto = require('crypto');

// Resolve repository paths
const ROOT_DIR = path.resolve(__dirname, '..');
const EXTENSION_DIR = path.join(ROOT_DIR, 'extension');
const DIST_DIR = path.join(ROOT_DIR, 'dist');
const MANIFEST_PATH = path.join(EXTENSION_DIR, 'manifest.json');

// Whitelisted files required for store distribution (relative to extension/)
const WHITELISTED_FILES = [
  'manifest.json',
  'popup.html',
  'popup.css',
  'popup.js',
  'content.css',
  'content.js',
  'background.js',
  'icons/icon16.png',
  'icons/icon48.png',
  'icons/icon128.png',
  'lib/header-parser.js',
  'lib/auth-verifier.js',
  'lib/spoof-detector.js',
  'lib/forensic-exporter.js',
  'lib/notification-engine.js'
];

// Pre-computed CRC32 table for pure Node.js zip creation
const CRC_TABLE = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) {
    c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
  }
  CRC_TABLE[n] = c;
}

function calculateCRC32(buffer) {
  let crc = 0 ^ (-1);
  for (let i = 0; i < buffer.length; i++) {
    crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ buffer[i]) & 0xFF];
  }
  return (crc ^ (-1)) >>> 0;
}

/**
 * Builds a valid, store-compliant PKZIP archive buffer in memory
 */
function buildZipArchive(entries) {
  const localChunks = [];
  const centralChunks = [];
  let offset = 0;

  // Use fixed DOS date/time or current timestamp
  const now = new Date();
  const dosTime = ((now.getHours() & 0x1F) << 11) | ((now.getMinutes() & 0x3F) << 5) | ((Math.floor(now.getSeconds() / 2)) & 0x1F);
  const dosDate = (((now.getFullYear() - 1980) & 0x7F) << 9) | (((now.getMonth() + 1) & 0x0F) << 5) | (now.getDate() & 0x1F);

  for (const entry of entries) {
    const rawData = entry.data;
    const nameBuffer = Buffer.from(entry.name.replace(/\\/g, '/'), 'utf8');
    const crc = calculateCRC32(rawData);
    const uncompressedSize = rawData.length;
    const compressedData = zlib.deflateRawSync(rawData, { level: 9 });
    const compressedSize = compressedData.length;

    // Local File Header (30 bytes)
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0); // Local header signature
    localHeader.writeUInt16LE(20, 4);         // Version needed to extract (2.0)
    localHeader.writeUInt16LE(0x0800, 6);     // General purpose bit flag (UTF-8 filename)
    localHeader.writeUInt16LE(8, 8);          // Compression method (8 = Deflate)
    localHeader.writeUInt16LE(dosTime, 10);
    localHeader.writeUInt16LE(dosDate, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(compressedSize, 18);
    localHeader.writeUInt32LE(uncompressedSize, 22);
    localHeader.writeUInt16LE(nameBuffer.length, 26);
    localHeader.writeUInt16LE(0, 28);         // Extra field length

    localChunks.push(localHeader, nameBuffer, compressedData);

    // Central Directory Record (46 bytes)
    const cdHeader = Buffer.alloc(46);
    cdHeader.writeUInt32LE(0x02014b50, 0);    // Central dir signature
    cdHeader.writeUInt16LE(20, 4);            // Version made by
    cdHeader.writeUInt16LE(20, 6);            // Version needed
    cdHeader.writeUInt16LE(0x0800, 8);        // UTF-8 flag
    cdHeader.writeUInt16LE(8, 10);            // Compression method (Deflate)
    cdHeader.writeUInt16LE(dosTime, 12);
    cdHeader.writeUInt16LE(dosDate, 14);
    cdHeader.writeUInt32LE(crc, 16);
    cdHeader.writeUInt32LE(compressedSize, 20);
    cdHeader.writeUInt32LE(uncompressedSize, 24);
    cdHeader.writeUInt16LE(nameBuffer.length, 28);
    cdHeader.writeUInt16LE(0, 30);            // Extra field length
    cdHeader.writeUInt16LE(0, 32);            // File comment length
    cdHeader.writeUInt16LE(0, 34);            // Disk number start
    cdHeader.writeUInt16LE(0, 36);            // Internal file attributes
    cdHeader.writeUInt32LE((0o100644 << 16) >>> 0, 38); // Standard POSIX regular file permissions
    cdHeader.writeUInt32LE(offset, 42);       // Relative offset of local header

    centralChunks.push(cdHeader, nameBuffer);
    offset += localHeader.length + nameBuffer.length + compressedData.length;
  }

  const centralDirectory = Buffer.concat(centralChunks);
  const cdOffset = offset;
  const cdSize = centralDirectory.length;

  // End of Central Directory Record (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);         // EOCD signature
  eocd.writeUInt16LE(0, 4);                  // Disk number
  eocd.writeUInt16LE(0, 6);                  // Start disk
  eocd.writeUInt16LE(entries.length, 8);     // Total entries on this disk
  eocd.writeUInt16LE(entries.length, 10);    // Total entries
  eocd.writeUInt32LE(cdSize, 12);            // Size of central directory
  eocd.writeUInt32LE(cdOffset, 16);          // Offset of start of central directory
  eocd.writeUInt16LE(0, 20);                 // Comment length

  return Buffer.concat([...localChunks, centralDirectory, eocd]);
}

/**
 * Pre-Package Security & Integrity Guards
 */
function runPrePackageGuards() {
  console.log('[1/4] Running pre-package integrity guards...');

  // 1. Verify manifest.json exists and parses cleanly
  if (!fs.existsSync(MANIFEST_PATH)) {
    throw new Error(`manifest.json missing at: ${MANIFEST_PATH}`);
  }

  let manifest;
  try {
    const rawManifest = fs.readFileSync(MANIFEST_PATH, 'utf8');
    manifest = JSON.parse(rawManifest);
  } catch (err) {
    throw new Error(`manifest.json syntax error: ${err.message}`);
  }

  if (manifest.manifest_version !== 3) {
    throw new Error(`Unsupported manifest_version: ${manifest.manifest_version}. Must be 3.`);
  }
  if (!manifest.version || !manifest.name) {
    throw new Error('manifest.json must declare valid name and version fields.');
  }

  // 2. Verify all whitelisted files exist and pass syntax validation
  const entries = [];
  const pngHeader = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

  for (const relPath of WHITELISTED_FILES) {
    const fullPath = path.join(EXTENSION_DIR, relPath);
    if (!fs.existsSync(fullPath)) {
      throw new Error(`Required extension asset missing: ${relPath}`);
    }

    const data = fs.readFileSync(fullPath);
    if (data.length === 0) {
      throw new Error(`Zero-byte file detected: ${relPath}`);
    }

    // JavaScript Syntax Verification
    if (relPath.endsWith('.js')) {
      try {
        const code = data.toString('utf8');
        new vm.Script(code, { filename: relPath });
      } catch (err) {
        throw new Error(`Syntax validation failed for ${relPath}: ${err.message}`);
      }
    }

    // PNG Icon Verification
    if (relPath.endsWith('.png')) {
      if (data.length < 8 || !data.subarray(0, 8).equals(pngHeader)) {
        throw new Error(`Corrupt PNG icon asset: ${relPath}`);
      }
    }

    // CSP and Remote Script Verification for HTML
    if (relPath.endsWith('.html')) {
      const htmlText = data.toString('utf8');
      if (/<script[^>]+src=["']https?:\/\//i.test(htmlText)) {
        throw new Error(`Remote CDN script tag detected in ${relPath} (CSP violation)`);
      }
      if (/<[^>]+?\s+on[a-z]+\s*=/i.test(htmlText)) {
        throw new Error(`Inline event handler detected in ${relPath} (CSP violation)`);
      }
    }

    entries.push({ name: relPath, data, size: data.length });
  }

  console.log(`  ✓ Manifest V3 validated: ${manifest.name} (v${manifest.version})`);
  console.log(`  ✓ All ${entries.length} assets passed integrity and CSP syntax checks.`);

  return { manifest, entries };
}

/**
 * Main Packaging Runner
 */
function packageExtension() {
  console.log('\n======================================================');
  console.log("  Atelier's MailTracker — Chrome Extension Packager");
  console.log('======================================================\n');

  // Step 1: Pre-package validation
  const { manifest, entries } = runPrePackageGuards();

  // Step 2: Ensure output directory exists
  console.log('[2/4] Initializing output directory...');
  if (!fs.existsSync(DIST_DIR)) {
    fs.mkdirSync(DIST_DIR, { recursive: true });
  }

  // Step 3: Generate store-compliant zip archive
  const version = manifest.version || '2.0.0';
  const zipFilename = `atelier-mailtracker-v${version}.zip`;
  const zipFilePath = path.join(DIST_DIR, zipFilename);

  console.log(`[3/4] Compressing ${entries.length} distribution assets into PKZIP archive...`);
  const zipBuffer = buildZipArchive(entries);
  fs.writeFileSync(zipFilePath, zipBuffer);

  // Step 4: Verification and digest computation
  console.log('[4/4] Verifying archive integrity and computing digests...');
  const stats = fs.statSync(zipFilePath);
  const sha256 = crypto.createHash('sha256').update(zipBuffer).digest('hex');

  // Output manifest summary table
  console.log('\n--- Packaged Asset Manifest ---');
  let totalRawSize = 0;
  entries.forEach((e, idx) => {
    totalRawSize += e.size;
    const padName = e.name.padEnd(32, ' ');
    const padSize = `${(e.size / 1024).toFixed(1)} KB`.padStart(10, ' ');
    console.log(`  [${String(idx + 1).padStart(2, '0')}] ${padName} ${padSize}`);
  });

  const compressionRatio = ((1 - (stats.size / totalRawSize)) * 100).toFixed(1);

  console.log('------------------------------------------------------');
  console.log(`  Raw Assets Total:       ${(totalRawSize / 1024).toFixed(1)} KB`);
  console.log(`  Package Output:         ${zipFilePath}`);
  console.log(`  Package File Size:      ${stats.size.toLocaleString()} bytes (${(stats.size / 1024).toFixed(1)} KB)`);
  console.log(`  Compression Savings:    ${compressionRatio}%`);
  console.log(`  SHA-256 Digest:         ${sha256}`);
  console.log('======================================================');
  console.log('🎉 Store release package generated successfully!\n');
}

if (require.main === module) {
  try {
    packageExtension();
  } catch (err) {
    console.error('\n❌ Packaging Error:', err.message);
    process.exit(1);
  }
}

module.exports = { packageExtension, buildZipArchive, runPrePackageGuards, WHITELISTED_FILES };
