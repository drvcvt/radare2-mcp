import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { R2Session } from '../r2/session.js';
import { sanitizePath } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';

// ---------------------------------------------------------------------------
// Byte-reading helpers
// ---------------------------------------------------------------------------

async function readBytes(session: R2Session, offset: number, count: number): Promise<Buffer> {
  const hex = await session.cmd(`p8 ${count} @ ${offset}`);
  return Buffer.from(hex.trim(), 'hex');
}

async function readU32LE(session: R2Session, offset: number): Promise<number> {
  const buf = await readBytes(session, offset, 4);
  return buf.readUInt32LE(0);
}

async function readU32BE(session: R2Session, offset: number): Promise<number> {
  const buf = await readBytes(session, offset, 4);
  return buf.readUInt32BE(0);
}

async function readU16LE(session: R2Session, offset: number): Promise<number> {
  const buf = await readBytes(session, offset, 2);
  return buf.readUInt16LE(0);
}

async function readU16BE(session: R2Session, offset: number): Promise<number> {
  const buf = await readBytes(session, offset, 2);
  return buf.readUInt16BE(0);
}

async function readAscii(session: R2Session, offset: number, count: number): Promise<string> {
  const buf = await readBytes(session, offset, count);
  return buf.toString('ascii');
}

async function readHexdump(
  session: R2Session,
  offset: number,
  count: number,
): Promise<string> {
  if (count === 0) return '';
  const raw = await session.cmd(`px ${count} @ ${offset}`);
  return raw.trim();
}

async function getFileSize(session: R2Session): Promise<number> {
  // Seek to end and get offset
  const raw = await session.cmd('i~size[1]');
  const trimmed = raw.trim();
  const parsed = parseInt(trimmed, 10);
  if (!isNaN(parsed) && parsed > 0) return parsed;

  // Fallback: seek to end
  await session.cmd('s+ 0');
  const endRaw = await session.cmd('s');
  return parseInt(endRaw.trim(), 10) || 0;
}

// ---------------------------------------------------------------------------
// Format number helpers
// ---------------------------------------------------------------------------

function fmtSize(size: number): string {
  if (size < 1024) return `${size.toLocaleString()} bytes`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

function fmtOffset(offset: number): string {
  return `0x${offset.toString(16).padStart(8, '0')}`;
}

// ---------------------------------------------------------------------------
// Magic signatures
// ---------------------------------------------------------------------------

interface MagicSignature {
  readonly magic: Buffer | string;
  readonly offset: number;
  readonly format: string;
  readonly label: string;
}

const MAGIC_SIGNATURES: MagicSignature[] = [
  { magic: 'RIFF', offset: 0, format: 'riff', label: 'RIFF Container' },
  {
    magic: Buffer.from([0x89, 0x50, 0x4e, 0x47]),
    offset: 0,
    format: 'png',
    label: 'PNG Image',
  },
  {
    magic: Buffer.from([0xff, 0xd8, 0xff]),
    offset: 0,
    format: 'jpeg',
    label: 'JPEG Image',
  },
  { magic: 'PK', offset: 0, format: 'zip', label: 'ZIP Archive' },
  { magic: '%PDF', offset: 0, format: 'pdf', label: 'PDF Document' },
  {
    magic: Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
    offset: 0,
    format: 'elf',
    label: 'ELF Executable',
  },
  { magic: 'MZ', offset: 0, format: 'pe', label: 'PE/EXE Executable' },
  { magic: 'GIF8', offset: 0, format: 'gif', label: 'GIF Image' },
  {
    magic: Buffer.from([0x1f, 0x8b]),
    offset: 0,
    format: 'gzip',
    label: 'GZIP Archive',
  },
  { magic: 'BM', offset: 0, format: 'bmp', label: 'BMP Image' },
  {
    magic: Buffer.from([0x00, 0x00, 0x01, 0x00]),
    offset: 0,
    format: 'ico',
    label: 'ICO Icon',
  },
  {
    magic: Buffer.from([0x4f, 0x67, 0x67, 0x53]),
    offset: 0,
    format: 'ogg',
    label: 'OGG Audio',
  },
  { magic: 'fLaC', offset: 0, format: 'flac', label: 'FLAC Audio' },
];

function detectFormat(
  headerBuf: Buffer,
): { format: string; label: string } | undefined {
  for (const sig of MAGIC_SIGNATURES) {
    const magicBuf =
      typeof sig.magic === 'string' ? Buffer.from(sig.magic, 'ascii') : sig.magic;
    const slice = headerBuf.subarray(sig.offset, sig.offset + magicBuf.length);
    if (slice.length === magicBuf.length && slice.equals(magicBuf)) {
      return { format: sig.format, label: sig.label };
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Chunk descriptor
// ---------------------------------------------------------------------------

interface ChunkInfo {
  readonly index: number;
  readonly offset: number;
  readonly tag: string;
  readonly size: number;
  readonly description: string;
  readonly details?: string | undefined;
  readonly hexdump?: string | undefined;
  readonly children?: ChunkInfo[] | undefined;
}

// ---------------------------------------------------------------------------
// RIFF/WebP parser
// ---------------------------------------------------------------------------

const WEBP_CHUNK_DESCRIPTIONS: Record<string, string> = {
  'VP8 ': 'Lossy image data',
  VP8L: 'Lossless image data',
  VP8X: 'Extended format',
  ALPH: 'Alpha channel data',
  ANIM: 'Animation parameters',
  ANMF: 'Animation frame',
  ICCP: 'ICC color profile',
  EXIF: 'EXIF metadata',
  'XMP ': 'XMP metadata',
};

function describeRiffChunk(fourcc: string, riffFormat: string): string {
  if (riffFormat === 'WEBP') {
    const desc = WEBP_CHUNK_DESCRIPTIONS[fourcc];
    if (desc) return desc;
  }
  return `${fourcc} chunk`;
}

async function parseVp8xDetails(session: R2Session, dataOffset: number): Promise<string> {
  const flagsBuf = await readBytes(session, dataOffset, 4);
  const flags = flagsBuf.readUInt32LE(0);

  const hasIcc = (flags & 0x20) !== 0;
  const hasAlpha = (flags & 0x10) !== 0;
  const hasExif = (flags & 0x08) !== 0;
  const hasXmp = (flags & 0x04) !== 0;
  const hasAnimation = (flags & 0x02) !== 0;

  // Canvas width: 24-bit LE at offset 4 within data (+1)
  const widthBuf = await readBytes(session, dataOffset + 4, 3);
  const width = (widthBuf[0]! | (widthBuf[1]! << 8) | (widthBuf[2]! << 16)) + 1;

  // Canvas height: 24-bit LE at offset 7 within data (+1)
  const heightBuf = await readBytes(session, dataOffset + 7, 3);
  const height = (heightBuf[0]! | (heightBuf[1]! << 8) | (heightBuf[2]! << 16)) + 1;

  const lines = [
    '#### VP8X (Extended Format)',
    '| Feature | Status |',
    '|---------|--------|',
    `| Has alpha | ${hasAlpha ? 'yes' : 'no'} |`,
    `| Has animation | ${hasAnimation ? 'yes' : 'no'} |`,
    `| Has EXIF | ${hasExif ? 'yes' : 'no'} |`,
    `| Has XMP | ${hasXmp ? 'yes' : 'no'} |`,
    `| Has ICC | ${hasIcc ? 'yes' : 'no'} |`,
    `| Canvas | ${width} x ${height} |`,
  ];
  return lines.join('\n');
}

async function parseVp8Details(session: R2Session, dataOffset: number): Promise<string> {
  const header = await readBytes(session, dataOffset, 10);
  const frameTag =
    (header[0]! | (header[1]! << 8) | (header[2]! << 16)) >>> 0;
  const isKeyframe = (frameTag & 0x01) === 0;
  const version = (frameTag >> 1) & 0x07;

  const lines = ['#### VP8 (Lossy Image)'];
  lines.push('| Property | Value |');
  lines.push('|----------|-------|');
  lines.push(`| Keyframe | ${isKeyframe ? 'yes' : 'no'} |`);
  lines.push(`| Version | ${version} |`);

  if (isKeyframe && header.length >= 10) {
    // Check for magic 0x9d012a at bytes 3-5
    if (header[3] === 0x9d && header[4] === 0x01 && header[5] === 0x2a) {
      const width = header.readUInt16LE(6) & 0x3fff;
      const height = header.readUInt16LE(8) & 0x3fff;
      lines.push(`| Width | ${width} |`);
      lines.push(`| Height | ${height} |`);
    }
  }

  return lines.join('\n');
}

async function parseAnimDetails(session: R2Session, dataOffset: number): Promise<string> {
  const bgBuf = await readBytes(session, dataOffset, 4);
  const bg = `#${bgBuf.toString('hex')}`;
  const loopCount = await readU16LE(session, dataOffset + 4);

  const lines = [
    '#### ANIM (Animation Parameters)',
    '| Property | Value |',
    '|----------|-------|',
    `| Background color | ${bg} |`,
    `| Loop count | ${loopCount === 0 ? 'infinite' : String(loopCount)} |`,
  ];
  return lines.join('\n');
}

async function parseRiff(
  session: R2Session,
  fileSize: number,
  maxChunks: number,
  hexdumpSize: number,
): Promise<{ containerInfo: string; chunks: ChunkInfo[] }> {
  const riffSize = await readU32LE(session, 4);
  const riffFormat = await readAscii(session, 8, 4);

  let formatLabel = riffFormat;
  if (riffFormat === 'WEBP') formatLabel = 'WebP';
  else if (riffFormat.startsWith('AVI')) formatLabel = 'AVI';
  else if (riffFormat === 'WAVE') formatLabel = 'WAV';

  const containerInfo = [
    `### Container: RIFF/${formatLabel}`,
    '| Property | Value |',
    '|----------|-------|',
    `| Container Size | ${fmtSize(riffSize + 8)} |`,
    `| Format | ${riffFormat} |`,
  ].join('\n');

  const chunks: ChunkInfo[] = [];
  let offset = 12; // After RIFF header
  const endOffset = Math.min(riffSize + 8, fileSize);

  while (offset + 8 <= endOffset && chunks.length < maxChunks) {
    const fourcc = await readAscii(session, offset, 4);
    const chunkSize = await readU32LE(session, offset + 4);
    const dataOffset = offset + 8;

    const description = describeRiffChunk(fourcc, riffFormat);

    let details: string | undefined;
    if (riffFormat === 'WEBP') {
      if (fourcc === 'VP8X') {
        details = await parseVp8xDetails(session, dataOffset);
      } else if (fourcc === 'VP8 ') {
        details = await parseVp8Details(session, dataOffset);
      } else if (fourcc === 'ANIM') {
        details = await parseAnimDetails(session, dataOffset);
      }
    }

    let hexdump: string | undefined;
    if (hexdumpSize > 0) {
      const dumpCount = Math.min(hexdumpSize, chunkSize);
      if (dumpCount > 0) {
        hexdump = await readHexdump(session, dataOffset, dumpCount);
      }
    }

    // Parse ANMF sub-chunks for animation frames
    let children: ChunkInfo[] | undefined;
    if (fourcc === 'ANMF' && chunkSize > 16 && riffFormat === 'WEBP') {
      children = [];
      let subOffset = dataOffset + 16; // Skip ANMF header (16 bytes)
      const subEnd = Math.min(dataOffset + chunkSize, endOffset);
      while (subOffset + 8 <= subEnd && children.length < maxChunks - chunks.length) {
        const subFourcc = await readAscii(session, subOffset, 4);
        const subSize = await readU32LE(session, subOffset + 4);
        children.push({
          index: children.length + 1,
          offset: subOffset,
          tag: subFourcc,
          size: subSize,
          description: describeRiffChunk(subFourcc, riffFormat),
        });
        subOffset += 8 + subSize + (subSize % 2);
      }
    }

    chunks.push({
      index: chunks.length + 1,
      offset,
      tag: fourcc,
      size: chunkSize,
      description,
      details,
      hexdump,
      children,
    });

    // Advance past chunk (pad to even boundary)
    offset = dataOffset + chunkSize + (chunkSize % 2);
  }

  return { containerInfo, chunks };
}

// ---------------------------------------------------------------------------
// PNG parser
// ---------------------------------------------------------------------------

const PNG_COLOR_TYPES: Record<number, string> = {
  0: 'Grayscale',
  2: 'RGB',
  3: 'Indexed',
  4: 'Grayscale+Alpha',
  6: 'RGBA',
};

async function parseIhdr(session: R2Session, dataOffset: number): Promise<string> {
  const width = await readU32BE(session, dataOffset);
  const height = await readU32BE(session, dataOffset + 4);
  const bitDepthBuf = await readBytes(session, dataOffset + 8, 1);
  const colorTypeBuf = await readBytes(session, dataOffset + 9, 1);
  const compressionBuf = await readBytes(session, dataOffset + 10, 1);
  const filterBuf = await readBytes(session, dataOffset + 11, 1);
  const interlaceBuf = await readBytes(session, dataOffset + 12, 1);

  const bitDepth = bitDepthBuf[0]!;
  const colorType = colorTypeBuf[0]!;
  const compression = compressionBuf[0]!;
  const filter = filterBuf[0]!;
  const interlace = interlaceBuf[0]!;

  return [
    '#### IHDR (Image Header)',
    '| Property | Value |',
    '|----------|-------|',
    `| Width | ${width} |`,
    `| Height | ${height} |`,
    `| Bit depth | ${bitDepth} |`,
    `| Color type | ${colorType} (${PNG_COLOR_TYPES[colorType] ?? 'Unknown'}) |`,
    `| Compression | ${compression} |`,
    `| Filter | ${filter} |`,
    `| Interlace | ${interlace === 1 ? 'Adam7' : 'None'} |`,
  ].join('\n');
}

async function parsePng(
  session: R2Session,
  fileSize: number,
  maxChunks: number,
  hexdumpSize: number,
): Promise<{ containerInfo: string; chunks: ChunkInfo[] }> {
  const containerInfo = [
    '### Container: PNG',
    '| Property | Value |',
    '|----------|-------|',
    `| Signature | 89 50 4E 47 0D 0A 1A 0A |`,
  ].join('\n');

  const chunks: ChunkInfo[] = [];
  let offset = 8; // After 8-byte PNG signature

  while (offset + 12 <= fileSize && chunks.length < maxChunks) {
    const length = await readU32BE(session, offset);
    const type = await readAscii(session, offset + 4, 4);
    const dataOffset = offset + 8;

    let description = `${type} chunk`;
    if (type === 'IHDR') description = 'Image header';
    else if (type === 'IDAT') description = 'Compressed image data';
    else if (type === 'IEND') description = 'Image end marker';
    else if (type === 'PLTE') description = 'Palette';
    else if (type === 'tEXt') description = 'Text metadata';
    else if (type === 'zTXt') description = 'Compressed text metadata';
    else if (type === 'iTXt') description = 'International text metadata';
    else if (type === 'gAMA') description = 'Gamma';
    else if (type === 'cHRM') description = 'Chromaticities';
    else if (type === 'sRGB') description = 'sRGB rendering intent';
    else if (type === 'iCCP') description = 'ICC profile';
    else if (type === 'tIME') description = 'Last modification time';
    else if (type === 'pHYs') description = 'Physical pixel dimensions';
    else if (type === 'bKGD') description = 'Background color';
    else if (type === 'tRNS') description = 'Transparency';
    else if (type === 'sBIT') description = 'Significant bits';

    let details: string | undefined;
    if (type === 'IHDR' && length >= 13) {
      details = await parseIhdr(session, dataOffset);
    } else if ((type === 'tEXt' || type === 'zTXt' || type === 'iTXt') && length > 0) {
      // Try to read text content (keyword is null-terminated)
      const textLen = Math.min(length, 200);
      const textBuf = await readBytes(session, dataOffset, textLen);
      const nullIdx = textBuf.indexOf(0);
      if (nullIdx >= 0) {
        const keyword = textBuf.subarray(0, nullIdx).toString('ascii');
        let value = '';
        if (type === 'tEXt') {
          value = textBuf.subarray(nullIdx + 1).toString('utf8');
        } else {
          value = '(compressed)';
        }
        details = [
          `#### ${type} (Text)`,
          `| Property | Value |`,
          `|----------|-------|`,
          `| Keyword | ${keyword} |`,
          `| Value | ${value.slice(0, 100)} |`,
        ].join('\n');
      }
    }

    let hexdump: string | undefined;
    if (hexdumpSize > 0 && length > 0) {
      const dumpCount = Math.min(hexdumpSize, length);
      hexdump = await readHexdump(session, dataOffset, dumpCount);
    }

    chunks.push({
      index: chunks.length + 1,
      offset,
      tag: type,
      size: length,
      description,
      details,
      hexdump,
    });

    // length + 4 (type) + 4 (length) + 4 (crc)
    offset = dataOffset + length + 4;

    if (type === 'IEND') break;
  }

  return { containerInfo, chunks };
}

// ---------------------------------------------------------------------------
// JPEG parser
// ---------------------------------------------------------------------------

const JPEG_MARKER_NAMES: Record<number, string> = {
  0xd8: 'SOI (Start of Image)',
  0xd9: 'EOI (End of Image)',
  0xda: 'SOS (Start of Scan)',
  0xdb: 'DQT (Quantization Table)',
  0xc0: 'SOF0 (Baseline DCT)',
  0xc1: 'SOF1 (Extended Sequential)',
  0xc2: 'SOF2 (Progressive DCT)',
  0xc4: 'DHT (Huffman Table)',
  0xdd: 'DRI (Restart Interval)',
  0xe0: 'APP0 (JFIF)',
  0xe1: 'APP1 (EXIF/XMP)',
  0xe2: 'APP2',
  0xfe: 'COM (Comment)',
};

async function parseJpeg(
  session: R2Session,
  fileSize: number,
  maxChunks: number,
  hexdumpSize: number,
): Promise<{ containerInfo: string; chunks: ChunkInfo[] }> {
  const containerInfo = [
    '### Container: JPEG',
    '| Property | Value |',
    '|----------|-------|',
    `| Signature | FF D8 |`,
  ].join('\n');

  const chunks: ChunkInfo[] = [];
  let offset = 0;

  while (offset < fileSize && chunks.length < maxChunks) {
    const markerBuf = await readBytes(session, offset, 2);
    if (markerBuf[0] !== 0xff) break;

    const marker = markerBuf[1]!;
    const markerName = JPEG_MARKER_NAMES[marker] ?? `Marker 0x${marker.toString(16)}`;

    // SOI and EOI have no payload
    if (marker === 0xd8 || marker === 0xd9) {
      chunks.push({
        index: chunks.length + 1,
        offset,
        tag: `FF ${marker.toString(16).toUpperCase().padStart(2, '0')}`,
        size: 0,
        description: markerName,
      });
      offset += 2;
      if (marker === 0xd9) break;
      continue;
    }

    // Skip fill bytes (0xFF)
    if (marker === 0xff || marker === 0x00) {
      offset += 1;
      continue;
    }

    // Restart markers (D0-D7) have no payload
    if (marker >= 0xd0 && marker <= 0xd7) {
      chunks.push({
        index: chunks.length + 1,
        offset,
        tag: `FF ${marker.toString(16).toUpperCase().padStart(2, '0')}`,
        size: 0,
        description: `RST${marker - 0xd0} (Restart)`,
      });
      offset += 2;
      continue;
    }

    // All other markers: 2 bytes length (includes length field itself)
    if (offset + 4 > fileSize) break;
    const segLen = await readU16BE(session, offset + 2);
    const dataOffset = offset + 4;
    const dataLen = segLen - 2;

    let details: string | undefined;

    // Parse SOF0/SOF2 for image dimensions
    if ((marker === 0xc0 || marker === 0xc2) && dataLen >= 5) {
      const precBuf = await readBytes(session, dataOffset, 1);
      const precision = precBuf[0]!;
      const height = await readU16BE(session, dataOffset + 1);
      const width = await readU16BE(session, dataOffset + 3);
      const compBuf = await readBytes(session, dataOffset + 5, 1);
      const components = compBuf[0]!;

      details = [
        `#### ${marker === 0xc0 ? 'SOF0 (Baseline)' : 'SOF2 (Progressive)'}`,
        '| Property | Value |',
        '|----------|-------|',
        `| Width | ${width} |`,
        `| Height | ${height} |`,
        `| Precision | ${precision} bits |`,
        `| Components | ${components} |`,
      ].join('\n');
    }

    // Parse COM for comment text
    if (marker === 0xfe && dataLen > 0) {
      const commentLen = Math.min(dataLen, 200);
      const commentBuf = await readBytes(session, dataOffset, commentLen);
      const comment = commentBuf.toString('utf8').replace(/\0/g, '');
      details = [
        '#### COM (Comment)',
        `| Content | ${comment.slice(0, 100)} |`,
      ].join('\n');
    }

    let hexdump: string | undefined;
    if (hexdumpSize > 0 && dataLen > 0) {
      const dumpCount = Math.min(hexdumpSize, dataLen);
      hexdump = await readHexdump(session, dataOffset, dumpCount);
    }

    chunks.push({
      index: chunks.length + 1,
      offset,
      tag: `FF ${marker.toString(16).toUpperCase().padStart(2, '0')}`,
      size: dataLen,
      description: markerName,
      details,
      hexdump,
    });

    offset = dataOffset + dataLen;

    // Stop parsing after SOS -- rest is compressed data
    if (marker === 0xda) {
      chunks.push({
        index: chunks.length + 1,
        offset,
        tag: '...',
        size: fileSize - offset - 2, // Exclude EOI
        description: 'Compressed scan data (not parsed)',
      });
      break;
    }
  }

  return { containerInfo, chunks };
}

// ---------------------------------------------------------------------------
// ZIP parser
// ---------------------------------------------------------------------------

const ZIP_COMPRESSION_METHODS: Record<number, string> = {
  0: 'Stored (no compression)',
  1: 'Shrunk',
  6: 'Imploded',
  8: 'Deflated',
  9: 'Deflate64',
  12: 'BZIP2',
  14: 'LZMA',
  93: 'Zstandard',
  98: 'PPMd',
};

async function parseZip(
  session: R2Session,
  fileSize: number,
  maxChunks: number,
  hexdumpSize: number,
): Promise<{ containerInfo: string; chunks: ChunkInfo[] }> {
  const containerInfo = [
    '### Container: ZIP',
    '| Property | Value |',
    '|----------|-------|',
    `| Signature | PK (50 4B) |`,
  ].join('\n');

  const chunks: ChunkInfo[] = [];
  let offset = 0;

  while (offset + 30 <= fileSize && chunks.length < maxChunks) {
    // Check for PK signature
    const sig = await readBytes(session, offset, 4);
    const sigVal = sig.readUInt32LE(0);

    // Local file header: PK\x03\x04
    if (sigVal === 0x04034b50) {
      const compressionMethod = await readU16LE(session, offset + 8);
      const crc32 = await readU32LE(session, offset + 14);
      const compressedSize = await readU32LE(session, offset + 18);
      const uncompressedSize = await readU32LE(session, offset + 22);
      const nameLen = await readU16LE(session, offset + 26);
      const extraLen = await readU16LE(session, offset + 28);

      let filename = '(unknown)';
      if (nameLen > 0 && nameLen < 512) {
        filename = await readAscii(session, offset + 30, nameLen);
      }

      const methodName = ZIP_COMPRESSION_METHODS[compressionMethod] ?? `Method ${compressionMethod}`;

      const details = [
        `#### ${filename}`,
        '| Property | Value |',
        '|----------|-------|',
        `| Compression | ${methodName} |`,
        `| Compressed | ${fmtSize(compressedSize)} |`,
        `| Uncompressed | ${fmtSize(uncompressedSize)} |`,
        `| CRC-32 | ${crc32.toString(16).padStart(8, '0')} |`,
      ].join('\n');

      let hexdump: string | undefined;
      if (hexdumpSize > 0 && compressedSize > 0) {
        const dumpOffset = offset + 30 + nameLen + extraLen;
        const dumpCount = Math.min(hexdumpSize, compressedSize);
        hexdump = await readHexdump(session, dumpOffset, dumpCount);
      }

      chunks.push({
        index: chunks.length + 1,
        offset,
        tag: 'FILE',
        size: compressedSize,
        description: filename,
        details,
        hexdump,
      });

      offset = offset + 30 + nameLen + extraLen + compressedSize;
      continue;
    }

    // Central directory header: PK\x01\x02
    if (sigVal === 0x02014b50) {
      const nameLen = await readU16LE(session, offset + 28);
      const extraLen = await readU16LE(session, offset + 30);
      const commentLen = await readU16LE(session, offset + 32);

      let filename = '(unknown)';
      if (nameLen > 0 && nameLen < 512) {
        filename = await readAscii(session, offset + 46, nameLen);
      }

      chunks.push({
        index: chunks.length + 1,
        offset,
        tag: 'CDIR',
        size: 46 + nameLen + extraLen + commentLen,
        description: `Central dir: ${filename}`,
      });

      offset += 46 + nameLen + extraLen + commentLen;
      continue;
    }

    // End of central directory: PK\x05\x06
    if (sigVal === 0x06054b50) {
      chunks.push({
        index: chunks.length + 1,
        offset,
        tag: 'EOCD',
        size: 22,
        description: 'End of central directory',
      });
      break;
    }

    // Unknown record — stop parsing
    break;
  }

  return { containerInfo, chunks };
}

// ---------------------------------------------------------------------------
// PDF parser (lightweight)
// ---------------------------------------------------------------------------

async function parsePdf(
  session: R2Session,
  fileSize: number,
  maxChunks: number,
  hexdumpSize: number,
): Promise<{ containerInfo: string; chunks: ChunkInfo[] }> {
  // Read PDF version from header
  const headerBuf = await readBytes(session, 0, Math.min(16, fileSize));
  const header = headerBuf.toString('ascii');
  const versionMatch = /%PDF-(\d+\.\d+)/.exec(header);
  const version = versionMatch ? versionMatch[1]! : 'unknown';

  const containerInfo = [
    '### Container: PDF',
    '| Property | Value |',
    '|----------|-------|',
    `| Version | ${version} |`,
  ].join('\n');

  // Scan for object definitions and major structures
  const chunks: ChunkInfo[] = [];
  const scanSize = Math.min(fileSize, 64 * 1024); // Scan first 64KB
  const blockSize = 4096;

  for (let off = 0; off < scanSize && chunks.length < maxChunks; off += blockSize) {
    const readCount = Math.min(blockSize, scanSize - off);
    const block = await readBytes(session, off, readCount);
    const text = block.toString('ascii');

    // Find object definitions (N N obj)
    const objRe = /(\d+)\s+(\d+)\s+obj/g;
    let match: RegExpExecArray | null;
    while ((match = objRe.exec(text)) !== null && chunks.length < maxChunks) {
      const objNum = match[1]!;
      const genNum = match[2]!;
      const objOffset = off + match.index;

      // Try to find if it's a stream object
      const remaining = text.substring(match.index, Math.min(match.index + 200, text.length));
      let description = `Object ${objNum} ${genNum}`;

      if (remaining.includes('/Type /Catalog')) description += ' (Catalog)';
      else if (remaining.includes('/Type /Page')) description += ' (Page)';
      else if (remaining.includes('/Type /Font')) description += ' (Font)';
      else if (remaining.includes('/Type /XObject')) description += ' (XObject)';
      else if (remaining.includes('stream')) description += ' (Stream)';

      let hexdump: string | undefined;
      if (hexdumpSize > 0) {
        hexdump = await readHexdump(session, objOffset, Math.min(hexdumpSize, 64));
      }

      chunks.push({
        index: chunks.length + 1,
        offset: objOffset,
        tag: 'obj',
        size: 0,
        description,
        hexdump,
      });
    }

    // Find xref table
    const xrefIdx = text.indexOf('xref');
    if (xrefIdx >= 0 && chunks.length < maxChunks) {
      chunks.push({
        index: chunks.length + 1,
        offset: off + xrefIdx,
        tag: 'xref',
        size: 0,
        description: 'Cross-reference table',
      });
    }

    // Find trailer
    const trailerIdx = text.indexOf('trailer');
    if (trailerIdx >= 0 && chunks.length < maxChunks) {
      chunks.push({
        index: chunks.length + 1,
        offset: off + trailerIdx,
        tag: 'trailer',
        size: 0,
        description: 'Trailer dictionary',
      });
    }
  }

  return { containerInfo, chunks };
}

// ---------------------------------------------------------------------------
// GIF parser
// ---------------------------------------------------------------------------

async function parseGif(
  session: R2Session,
  fileSize: number,
  maxChunks: number,
  hexdumpSize: number,
): Promise<{ containerInfo: string; chunks: ChunkInfo[] }> {
  const version = await readAscii(session, 0, 6);
  const width = await readU16LE(session, 6);
  const height = await readU16LE(session, 8);
  const packedBuf = await readBytes(session, 10, 1);
  const packed = packedBuf[0]!;
  const hasGct = (packed & 0x80) !== 0;
  const gctSize = hasGct ? 3 * (1 << ((packed & 0x07) + 1)) : 0;

  const containerInfo = [
    '### Container: GIF',
    '| Property | Value |',
    '|----------|-------|',
    `| Version | ${version} |`,
    `| Canvas | ${width} x ${height} |`,
    `| Global Color Table | ${hasGct ? `yes (${gctSize} bytes)` : 'no'} |`,
  ].join('\n');

  const chunks: ChunkInfo[] = [];
  let offset = 13 + gctSize; // Skip header + GCT

  while (offset < fileSize && chunks.length < maxChunks) {
    const introBuf = await readBytes(session, offset, 1);
    const intro = introBuf[0]!;

    if (intro === 0x3b) {
      // Trailer
      chunks.push({
        index: chunks.length + 1,
        offset,
        tag: '0x3B',
        size: 1,
        description: 'Trailer (end of GIF)',
      });
      break;
    }

    if (intro === 0x2c) {
      // Image descriptor
      if (offset + 10 > fileSize) break;
      const imgW = await readU16LE(session, offset + 5);
      const imgH = await readU16LE(session, offset + 7);

      chunks.push({
        index: chunks.length + 1,
        offset,
        tag: '0x2C',
        size: 0,
        description: `Image descriptor (${imgW}x${imgH})`,
      });

      // Skip image descriptor and sub-blocks
      offset += 10;
      const imgPackedBuf = await readBytes(session, offset - 1, 1);
      const imgPacked = imgPackedBuf[0]!;
      const hasLct = (imgPacked & 0x80) !== 0;
      if (hasLct) {
        offset += 3 * (1 << ((imgPacked & 0x07) + 1));
      }
      offset += 1; // LZW minimum code size

      // Skip sub-blocks
      while (offset < fileSize) {
        const sbBuf = await readBytes(session, offset, 1);
        const sbSize = sbBuf[0]!;
        offset += 1 + sbSize;
        if (sbSize === 0) break;
      }
      continue;
    }

    if (intro === 0x21) {
      // Extension block
      if (offset + 2 > fileSize) break;
      const labelBuf = await readBytes(session, offset + 1, 1);
      const label = labelBuf[0]!;

      let desc = 'Extension';
      if (label === 0xf9) desc = 'Graphic Control Extension';
      else if (label === 0xfe) desc = 'Comment Extension';
      else if (label === 0x01) desc = 'Plain Text Extension';
      else if (label === 0xff) desc = 'Application Extension';

      let hexdump: string | undefined;
      if (hexdumpSize > 0) {
        hexdump = await readHexdump(session, offset, Math.min(hexdumpSize, 20));
      }

      chunks.push({
        index: chunks.length + 1,
        offset,
        tag: `0x21 ${label.toString(16).padStart(2, '0')}`,
        size: 0,
        description: desc,
        hexdump,
      });

      // Skip extension sub-blocks
      offset += 2;
      while (offset < fileSize) {
        const sbBuf = await readBytes(session, offset, 1);
        const sbSize = sbBuf[0]!;
        offset += 1 + sbSize;
        if (sbSize === 0) break;
      }
      continue;
    }

    // Unknown byte — skip
    offset += 1;
  }

  return { containerInfo, chunks };
}

// ---------------------------------------------------------------------------
// Executable stub (ELF / PE)
// ---------------------------------------------------------------------------

function executableStub(format: string): { containerInfo: string; chunks: ChunkInfo[] } {
  const containerInfo = [
    `### Format: ${format === 'elf' ? 'ELF Executable' : 'PE/EXE Executable'}`,
    '',
    'Use `triage_binary` or `analyze_binary` for detailed executable analysis.',
  ].join('\n');
  return { containerInfo, chunks: [] };
}

// ---------------------------------------------------------------------------
// Generic / unknown format
// ---------------------------------------------------------------------------

async function parseUnknown(
  session: R2Session,
  fileSize: number,
): Promise<{ containerInfo: string; chunks: ChunkInfo[] }> {
  const dumpSize = Math.min(64, fileSize);
  const hexdump = await readHexdump(session, 0, dumpSize);

  const containerInfo = [
    '### Unknown Format',
    '',
    'No recognized file format signature detected.',
    '',
    '```',
    hexdump,
    '```',
  ].join('\n');

  return { containerInfo, chunks: [] };
}

// ---------------------------------------------------------------------------
// Output formatter
// ---------------------------------------------------------------------------

function formatOutput(
  filePath: string,
  fileSize: number,
  formatLabel: string,
  containerInfo: string,
  chunks: ChunkInfo[],
): string {
  const lines: string[] = [];

  lines.push('## File Format Analysis');
  lines.push('');
  lines.push('### File Info');
  lines.push('| Property | Value |');
  lines.push('|----------|-------|');
  lines.push(`| File | \`${filePath}\` |`);
  lines.push(`| Size | ${fmtSize(fileSize)} |`);
  lines.push(`| Format | **${formatLabel}** |`);
  lines.push('');
  lines.push(containerInfo);

  if (chunks.length > 0) {
    lines.push('');
    lines.push('### Chunk Hierarchy');
    lines.push('');
    lines.push('| # | Offset | Tag | Size | Description |');
    lines.push('|--:|--------|-----|-----:|-------------|');

    for (const chunk of chunks) {
      lines.push(
        `| ${chunk.index} | \`${fmtOffset(chunk.offset)}\` | \`${chunk.tag}\` | ${chunk.size.toLocaleString()} | ${chunk.description} |`,
      );

      if (chunk.children) {
        for (const child of chunk.children) {
          lines.push(
            `|   | \`${fmtOffset(child.offset)}\` | \`  ${child.tag}\` | ${child.size.toLocaleString()} | ${child.description} |`,
          );
        }
      }
    }

    // Chunk details section
    const detailedChunks = chunks.filter((c) => c.details || c.hexdump);
    if (detailedChunks.length > 0) {
      lines.push('');
      lines.push('### Chunk Details');

      for (const chunk of detailedChunks) {
        if (chunk.details) {
          lines.push('');
          lines.push(`${chunk.details} @ \`${fmtOffset(chunk.offset)}\``);
        }

        if (chunk.hexdump) {
          lines.push('');
          lines.push('```hexdump');
          lines.push(chunk.hexdump);
          lines.push('```');
        }
      }
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

export function registerFileFormatAnalyzer(server: McpServer): void {
  server.tool(
    'file_format_analyzer',
    'Analyze binary file format structures: identify format via magic bytes, parse containers (RIFF/WebP, PNG, ZIP, JPEG, PDF), and show chunk hierarchy with offsets, sizes, and metadata.',
    {
      file_path: z.string().describe('Path to the file to analyze'),
      max_chunks: z
        .number()
        .int()
        .min(1)
        .max(500)
        .default(100)
        .describe('Maximum number of chunks/sections to parse'),
      hexdump_size: z
        .number()
        .int()
        .min(0)
        .max(256)
        .default(32)
        .describe('Bytes to hexdump from each chunk header (0 to disable)'),
    },
    async ({ file_path, max_chunks, hexdump_size }) => {
      let session: R2Session | undefined;
      try {
        const safePath = sanitizePath(file_path);
        session = await R2Session.open(safePath, ['-2', '-n']);

        const fileSize = await getFileSize(session);
        if (fileSize === 0) {
          return mcpError('File is empty (0 bytes)');
        }

        // Read first 16 bytes for magic detection
        const headerBuf = await readBytes(session, 0, Math.min(16, fileSize));
        const detected = detectFormat(headerBuf);

        let containerInfo: string;
        let chunks: ChunkInfo[];
        let formatLabel: string;

        if (!detected) {
          formatLabel = 'Unknown';
          const result = await parseUnknown(session, fileSize);
          containerInfo = result.containerInfo;
          chunks = result.chunks;
        } else {
          formatLabel = detected.label;

          switch (detected.format) {
            case 'riff': {
              const result = await parseRiff(session, fileSize, max_chunks, hexdump_size);
              containerInfo = result.containerInfo;
              chunks = result.chunks;
              // Refine label based on RIFF subtype
              const riffFormat = await readAscii(session, 8, 4);
              if (riffFormat === 'WEBP') formatLabel = 'WebP (RIFF container)';
              else if (riffFormat.startsWith('AVI')) formatLabel = 'AVI (RIFF container)';
              else if (riffFormat === 'WAVE') formatLabel = 'WAV (RIFF container)';
              else formatLabel = `RIFF/${riffFormat}`;
              break;
            }
            case 'png': {
              const result = await parsePng(session, fileSize, max_chunks, hexdump_size);
              containerInfo = result.containerInfo;
              chunks = result.chunks;
              break;
            }
            case 'jpeg': {
              const result = await parseJpeg(session, fileSize, max_chunks, hexdump_size);
              containerInfo = result.containerInfo;
              chunks = result.chunks;
              break;
            }
            case 'zip': {
              const result = await parseZip(session, fileSize, max_chunks, hexdump_size);
              containerInfo = result.containerInfo;
              chunks = result.chunks;
              break;
            }
            case 'pdf': {
              const result = await parsePdf(session, fileSize, max_chunks, hexdump_size);
              containerInfo = result.containerInfo;
              chunks = result.chunks;
              break;
            }
            case 'gif': {
              const result = await parseGif(session, fileSize, max_chunks, hexdump_size);
              containerInfo = result.containerInfo;
              chunks = result.chunks;
              break;
            }
            case 'elf':
            case 'pe': {
              const result = executableStub(detected.format);
              containerInfo = result.containerInfo;
              chunks = result.chunks;
              break;
            }
            default: {
              // Formats we recognize but don't deeply parse (gzip, bmp, ico, ogg, flac)
              const dumpSize = Math.min(64, fileSize);
              const hexdump = await readHexdump(session, 0, dumpSize);
              containerInfo = [
                `### Format: ${detected.label}`,
                '',
                'Deep parsing not yet implemented for this format.',
                '',
                '```hexdump',
                hexdump,
                '```',
              ].join('\n');
              chunks = [];
              break;
            }
          }
        }

        return mcpFormatted(
          formatOutput(safePath, fileSize, formatLabel, containerInfo, chunks),
        );
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      } finally {
        if (session) {
          await session.close();
        }
      }
    },
  );
}
