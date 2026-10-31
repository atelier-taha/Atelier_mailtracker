const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

// CRC32 implementation for PNG chunks
function makeCRCTable() {
  let c;
  const crcTable = [];
  for (let n = 0; n < 256; n++) {
    c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    crcTable[n] = c;
  }
  return crcTable;
}

const crcTable = makeCRCTable();

function crc32(buf) {
  let crc = 0 ^ (-1);
  for (let i = 0; i < buf.length; i++) {
    crc = (crc >>> 8) ^ crcTable[(crc ^ buf[i]) & 0xFF];
  }
  return (crc ^ (-1)) >>> 0;
}

function createChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);

  const typeBuf = Buffer.from(type, 'ascii');
  const body = Buffer.concat([typeBuf, data]);

  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);

  return Buffer.concat([len, body, crc]);
}

function generateIconPNG(size) {
  const width = size;
  const height = size;

  // IHDR chunk
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData.writeUInt8(8, 8); // bit depth 8
  ihdrData.writeUInt8(6, 9); // RGBA
  ihdrData.writeUInt8(0, 10); // compression
  ihdrData.writeUInt8(0, 11); // filter
  ihdrData.writeUInt8(0, 12); // interlace
  const ihdrChunk = createChunk('IHDR', ihdrData);

  // Raw image data: filter byte (0) + width * 4 bytes per scanline
  const rowBytes = 1 + width * 4;
  const rawData = Buffer.alloc(rowBytes * height);

  const center = size / 2;
  const radius = size * 0.44;
  const innerRadius = size * 0.22;

  for (let y = 0; y < height; y++) {
    const rowOffset = y * rowBytes;
    rawData.writeUInt8(0, rowOffset); // filter byte

    for (let x = 0; x < width; x++) {
      const pxOffset = rowOffset + 1 + x * 4;
      const dx = x - center + 0.5;
      const dy = y - center + 0.5;
      const dist = Math.sqrt(dx * dx + dy * dy);

      // Blue gradient circle with inner radar dot
      if (dist <= radius) {
        if (dist <= innerRadius) {
          // Inner emerald dot
          rawData.writeUInt8(34, pxOffset);     // R
          rawData.writeUInt8(197, pxOffset + 1); // G
          rawData.writeUInt8(94, pxOffset + 2);  // B
          rawData.writeUInt8(255, pxOffset + 3); // A
        } else if (dist > radius - (size * 0.12)) {
          // Outer ring
          rawData.writeUInt8(37, pxOffset);     // R (primary blue #2563eb)
          rawData.writeUInt8(99, pxOffset + 1);  // G
          rawData.writeUInt8(235, pxOffset + 2); // B
          rawData.writeUInt8(255, pxOffset + 3); // A
        } else {
          // Background light blue
          rawData.writeUInt8(239, pxOffset);     // R
          rawData.writeUInt8(246, pxOffset + 1); // G
          rawData.writeUInt8(255, pxOffset + 2); // B
          rawData.writeUInt8(240, pxOffset + 3); // A
        }
      } else {
        // Transparent outside
        rawData.writeUInt8(0, pxOffset);
        rawData.writeUInt8(0, pxOffset + 1);
        rawData.writeUInt8(0, pxOffset + 2);
        rawData.writeUInt8(0, pxOffset + 3);
      }
    }
  }

  const compressedData = zlib.deflateSync(rawData);
  const idatChunk = createChunk('IDAT', compressedData);
  const iendChunk = createChunk('IEND', Buffer.alloc(0));

  const pngSignature = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  return Buffer.concat([pngSignature, ihdrChunk, idatChunk, iendChunk]);
}

const iconsDir = path.join(__dirname, '..', 'extension', 'icons');
if (!fs.existsSync(iconsDir)) {
  fs.mkdirSync(iconsDir, { recursive: true });
}

[16, 48, 128].forEach((size) => {
  const iconBuf = generateIconPNG(size);
  const filePath = path.join(iconsDir, `icon${size}.png`);
  fs.writeFileSync(filePath, iconBuf);
  console.log(`Generated ${filePath} (${iconBuf.length} bytes)`);
});
