/**
 * Pure TypeScript In-Memory PCAP & PCAPNG Parser
 * Extracts protocol hierarchy, conversations, and flags unencrypted plaintext communications.
 * Runs entirely in memory without requiring external binaries (e.g. tshark/wireshark).
 */

export interface ParsedPacket {
  id: number;
  timestamp: string;
  source: string;
  destination: string;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'HTTP' | 'TLS' | 'ARP' | 'IPv4' | 'IPv6' | 'Other';
  length: number;
  info: string;
  isPlaintext: boolean;
  plaintextSnippet?: string;
  credentialsFound?: { type: string; details: string };
}

export interface Conversation {
  endpointA: string;
  endpointB: string;
  protocol: string;
  packets: number;
  bytes: number;
}

export interface PcapAnalysisResult {
  filename: string;
  format: 'PCAP' | 'PCAPNG' | 'Unknown';
  totalPackets: number;
  totalBytes: number;
  durationSeconds: number;
  protocols: Record<string, number>;
  plaintextWarningsCount: number;
  packets: ParsedPacket[];
  conversations: Conversation[];
  findings: {
    type: 'critical' | 'warning' | 'info';
    title: string;
    description: string;
    packetId?: number;
    details?: string;
  }[];
}

export function parsePcapBuffer(buffer: Buffer, filename: string): PcapAnalysisResult {
  if (buffer.length < 24) {
    throw new Error('File is too small to be a valid packet capture.');
  }

  // Check PCAPNG Section Header Block magic: 0x0A0D0D0A
  if (buffer.readUInt32BE(0) === 0x0a0d0d0a || buffer.readUInt32LE(0) === 0x0a0d0d0a) {
    return parsePcapNg(buffer, filename);
  }

  // Standard PCAP magic check
  const magic = buffer.readUInt32BE(0);
  let isLittleEndian = false;
  let isNano = false;

  if (magic === 0xa1b2c3d4) {
    isLittleEndian = false;
  } else if (magic === 0xd4c3b2a1) {
    isLittleEndian = true;
  } else if (magic === 0xa1b23c4d) {
    isLittleEndian = false;
    isNano = true;
  } else if (magic === 0x4d3cb2a1) {
    isLittleEndian = true;
    isNano = true;
  } else {
    throw new Error('Unrecognized packet capture magic header. Expected .pcap or .pcapng format.');
  }

  const readU16 = (offset: number) => isLittleEndian ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
  const readU32 = (offset: number) => isLittleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);

  const linkType = readU32(20); // 1 = Ethernet, 113 = Linux Cooked SLL

  const packets: ParsedPacket[] = [];
  const protocolsCount: Record<string, number> = {};
  const conversationsMap = new Map<string, Conversation>();
  const findings: PcapAnalysisResult['findings'] = [];

  let offset = 24;
  let packetIndex = 1;
  let firstTimestamp = 0;
  let lastTimestamp = 0;
  let totalBytes = 0;

  while (offset + 16 <= buffer.length && packetIndex <= 1000) {
    const tsSec = readU32(offset);
    const tsUsec = readU32(offset + 4);
    const inclLen = readU32(offset + 8);
    const origLen = readU32(offset + 12);
    offset += 16;

    if (offset + inclLen > buffer.length) {
      break;
    }

    const packetData = buffer.subarray(offset, offset + inclLen);
    offset += inclLen;
    totalBytes += origLen;

    const timeInSec = tsSec + (isNano ? tsUsec / 1e9 : tsUsec / 1e6);
    if (packetIndex === 1) firstTimestamp = timeInSec;
    lastTimestamp = timeInSec;
    const relTime = (timeInSec - firstTimestamp).toFixed(4) + 's';

    const parsed = parsePacketData(packetData, linkType, packetIndex, relTime);
    packets.push(parsed);

    protocolsCount[parsed.protocol] = (protocolsCount[parsed.protocol] || 0) + 1;

    // Build conversations
    if (parsed.source && parsed.destination && parsed.source !== 'Unknown') {
      const convKey = [parsed.source, parsed.destination].sort().join(' <-> ');
      const existing = conversationsMap.get(convKey);
      if (existing) {
        existing.packets += 1;
        existing.bytes += inclLen;
      } else {
        conversationsMap.set(convKey, {
          endpointA: parsed.source,
          endpointB: parsed.destination,
          protocol: parsed.protocol,
          packets: 1,
          bytes: inclLen,
        });
      }
    }

    if (parsed.isPlaintext && parsed.plaintextSnippet) {
      if (parsed.credentialsFound) {
        findings.push({
          type: 'critical',
          title: `Cleartext Credentials Exposed (${parsed.credentialsFound.type})`,
          description: `Sensitive authentication credentials were transmitted over unencrypted ${parsed.protocol} traffic.`,
          packetId: parsed.id,
          details: parsed.credentialsFound.details,
        });
      } else if (parsed.protocol === 'HTTP') {
        findings.push({
          type: 'warning',
          title: 'Unencrypted HTTP Web Traffic',
          description: `Cleartext HTTP requests or responses transmitted without TLS encryption. Vulnerable to interception and injection.`,
          packetId: parsed.id,
          details: parsed.plaintextSnippet.substring(0, 180),
        });
      }
    }

    packetIndex++;
  }

  // Deduplicate findings if too many identical
  const uniqueFindings = findings.slice(0, 15);

  const durationSeconds = Math.max(0, lastTimestamp - firstTimestamp);

  return {
    filename,
    format: 'PCAP',
    totalPackets: packets.length,
    totalBytes,
    durationSeconds: parseFloat(durationSeconds.toFixed(3)),
    protocols: protocolsCount,
    plaintextWarningsCount: uniqueFindings.filter(f => f.type === 'critical' || f.type === 'warning').length,
    packets,
    conversations: Array.from(conversationsMap.values()).sort((a, b) => b.bytes - a.bytes).slice(0, 20),
    findings: uniqueFindings,
  };
}

function parsePacketData(data: Buffer, linkType: number, packetId: number, relTime: string): ParsedPacket {
  let ipOffset = 14; // Default Ethernet header length

  if (linkType === 113) {
    // Linux Cooked SLL header is 16 bytes
    ipOffset = 16;
  } else if (linkType === 101 || linkType === 12) {
    // Raw IP
    ipOffset = 0;
  }

  if (data.length < ipOffset + 20) {
    return {
      id: packetId,
      timestamp: relTime,
      source: 'Local Link',
      destination: 'Local Link',
      protocol: 'Other',
      length: data.length,
      info: `Raw link-layer frame (${data.length} bytes)`,
      isPlaintext: false,
    };
  }

  // Check Ethernet type if linkType == 1 (Ethernet)
  let etherType = 0x0800;
  if (ipOffset === 14) {
    etherType = data.readUInt16BE(12);
  }

  if (etherType === 0x0806) {
    // ARP
    return {
      id: packetId,
      timestamp: relTime,
      source: 'ARP Request/Reply',
      destination: 'Broadcast',
      protocol: 'ARP',
      length: data.length,
      info: 'Address Resolution Protocol',
      isPlaintext: false,
    };
  }

  if (etherType === 0x86dd) {
    // IPv6
    const nextHeader = data[ipOffset + 6];
    const srcIp = formatIpv6(data.subarray(ipOffset + 8, ipOffset + 24));
    const dstIp = formatIpv6(data.subarray(ipOffset + 24, ipOffset + 40));
    return parseTransport(data, ipOffset + 40, nextHeader, srcIp, dstIp, packetId, relTime);
  }

  // IPv4
  const versionIhl = data[ipOffset];
  const ihl = (versionIhl & 0x0f) * 4;
  const ipProtocol = data[ipOffset + 9]; // 6=TCP, 17=UDP, 1=ICMP
  const srcIp = `${data[ipOffset + 12]}.${data[ipOffset + 13]}.${data[ipOffset + 14]}.${data[ipOffset + 15]}`;
  const dstIp = `${data[ipOffset + 16]}.${data[ipOffset + 17]}.${data[ipOffset + 18]}.${data[ipOffset + 19]}`;

  return parseTransport(data, ipOffset + ihl, ipProtocol, srcIp, dstIp, packetId, relTime);
}

function parseTransport(
  data: Buffer,
  transportOffset: number,
  ipProtocol: number,
  srcIp: string,
  dstIp: string,
  packetId: number,
  relTime: string
): ParsedPacket {
  if (data.length < transportOffset) {
    return {
      id: packetId,
      timestamp: relTime,
      source: srcIp,
      destination: dstIp,
      protocol: 'IPv4',
      length: data.length,
      info: `IP packet (proto ${ipProtocol})`,
      isPlaintext: false,
    };
  }

  if (ipProtocol === 1) {
    // ICMP
    const icmpType = data[transportOffset];
    const typeLabel = icmpType === 8 ? 'Echo Request (Ping)' : icmpType === 0 ? 'Echo Reply (Ping)' : `Type ${icmpType}`;
    return {
      id: packetId,
      timestamp: relTime,
      source: srcIp,
      destination: dstIp,
      protocol: 'ICMP',
      length: data.length,
      info: `ICMP ${typeLabel}`,
      isPlaintext: false,
    };
  }

  if (ipProtocol === 17) {
    // UDP
    if (data.length < transportOffset + 8) {
      return {
        id: packetId,
        timestamp: relTime,
        source: srcIp,
        destination: dstIp,
        protocol: 'UDP',
        length: data.length,
        info: 'Truncated UDP packet',
        isPlaintext: false,
      };
    }
    const srcPort = data.readUInt16BE(transportOffset);
    const dstPort = data.readUInt16BE(transportOffset + 2);
    const udpPayload = data.subarray(transportOffset + 8);

    if (srcPort === 53 || dstPort === 53) {
      // DNS inspection
      const queryName = extractDnsQueryName(udpPayload);
      return {
        id: packetId,
        timestamp: relTime,
        source: `${srcIp}:${srcPort}`,
        destination: `${dstIp}:${dstPort}`,
        protocol: 'DNS',
        length: data.length,
        info: queryName ? `DNS Query: ${queryName}` : 'DNS Standard Query/Response',
        isPlaintext: true,
        plaintextSnippet: queryName ? `Unencrypted DNS lookup for: ${queryName}` : undefined,
      };
    }

    return {
      id: packetId,
      timestamp: relTime,
      source: `${srcIp}:${srcPort}`,
      destination: `${dstIp}:${dstPort}`,
      protocol: 'UDP',
      length: data.length,
      info: `UDP ${srcPort} → ${dstPort} Len=${udpPayload.length}`,
      isPlaintext: false,
    };
  }

  if (ipProtocol === 6) {
    // TCP
    if (data.length < transportOffset + 20) {
      return {
        id: packetId,
        timestamp: relTime,
        source: srcIp,
        destination: dstIp,
        protocol: 'TCP',
        length: data.length,
        info: 'Truncated TCP packet',
        isPlaintext: false,
      };
    }
    const srcPort = data.readUInt16BE(transportOffset);
    const dstPort = data.readUInt16BE(transportOffset + 2);
    const dataOffset = ((data[transportOffset + 12] >> 4) & 0x0f) * 4;
    const tcpFlags = data[transportOffset + 13];

    const flagsList: string[] = [];
    if (tcpFlags & 0x02) flagsList.push('SYN');
    if (tcpFlags & 0x10) flagsList.push('ACK');
    if (tcpFlags & 0x01) flagsList.push('FIN');
    if (tcpFlags & 0x04) flagsList.push('RST');
    if (tcpFlags & 0x08) flagsList.push('PSH');

    const tcpPayload = data.subarray(transportOffset + dataOffset);

    // TLS Check (Port 443 or standard TLS record layer: 0x16 0x03 0x01/02/03)
    if (
      srcPort === 443 ||
      dstPort === 443 ||
      (tcpPayload.length >= 5 && tcpPayload[0] === 0x16 && tcpPayload[1] === 0x03)
    ) {
      return {
        id: packetId,
        timestamp: relTime,
        source: `${srcIp}:${srcPort}`,
        destination: `${dstIp}:${dstPort}`,
        protocol: 'TLS',
        length: data.length,
        info: `TLS Encrypted Traffic [${flagsList.join(', ') || 'DATA'}]`,
        isPlaintext: false,
      };
    }

    // Inspect TCP payload for plain text HTTP, FTP, Telnet
    if (tcpPayload.length > 4) {
      const payloadStr = tcpPayload.toString('latin1');

      // Check HTTP
      if (/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|HTTP\/1\.)\s/i.test(payloadStr)) {
        let creds: { type: string; details: string } | undefined;

        // Basic Auth check
        const authMatch = payloadStr.match(/Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i);
        if (authMatch && authMatch[1]) {
          try {
            const decoded = Buffer.from(authMatch[1], 'base64').toString('utf-8');
            creds = {
              type: 'HTTP Basic Auth',
              details: `Decoded credentials: "${decoded}" (Raw Header: ${authMatch[0]})`,
            };
          } catch {
            // ignore base64 decode failure
          }
        }

        // Form POST password check
        const formPasswordMatch = payloadStr.match(/(?:password|passwd|pwd|pass)=([^& \r\n]+)/i);
        if (formPasswordMatch) {
          creds = creds || {
            type: 'Plaintext Form Submission',
            details: `Intercepted form field: ${formPasswordMatch[0]}`,
          };
        }

        const firstLine = payloadStr.split('\r\n')[0] || payloadStr.split('\n')[0];
        return {
          id: packetId,
          timestamp: relTime,
          source: `${srcIp}:${srcPort}`,
          destination: `${dstIp}:${dstPort}`,
          protocol: 'HTTP',
          length: data.length,
          info: firstLine.substring(0, 80),
          isPlaintext: true,
          plaintextSnippet: payloadStr.substring(0, 240),
          credentialsFound: creds,
        };
      }

      // Check FTP
      if (/^(USER|PASS)\s/i.test(payloadStr)) {
        const cmdMatch = payloadStr.match(/^(USER|PASS)\s+(.*?)[\r\n]/i);
        const cmd = cmdMatch ? cmdMatch[1].toUpperCase() : 'FTP';
        const val = cmdMatch ? cmdMatch[2] : '';
        return {
          id: packetId,
          timestamp: relTime,
          source: `${srcIp}:${srcPort}`,
          destination: `${dstIp}:${dstPort}`,
          protocol: 'TCP',
          length: data.length,
          info: `FTP Command: ${cmd} ${val}`,
          isPlaintext: true,
          plaintextSnippet: payloadStr,
          credentialsFound: {
            type: 'FTP Plaintext Credentials',
            details: `Cleartext FTP ${cmd}: "${val}"`,
          },
        };
      }
    }

    const flagStr = flagsList.length ? `[${flagsList.join(', ')}]` : '[DATA]';
    return {
      id: packetId,
      timestamp: relTime,
      source: `${srcIp}:${srcPort}`,
      destination: `${dstIp}:${dstPort}`,
      protocol: 'TCP',
      length: data.length,
      info: `TCP ${srcPort} → ${dstPort} ${flagStr} Len=${tcpPayload.length}`,
      isPlaintext: false,
    };
  }

  return {
    id: packetId,
    timestamp: relTime,
    source: srcIp,
    destination: dstIp,
    protocol: 'Other',
    length: data.length,
    info: `Protocol ${ipProtocol}`,
    isPlaintext: false,
  };
}

function extractDnsQueryName(payload: Buffer): string | null {
  if (payload.length < 13) return null;
  let offset = 12; // DNS header is 12 bytes
  const parts: string[] = [];

  while (offset < payload.length) {
    const len = payload[offset];
    if (len === 0) break;
    if ((len & 0xc0) === 0xc0) {
      // DNS pointer compression
      break;
    }
    offset++;
    if (offset + len > payload.length) break;
    parts.push(payload.subarray(offset, offset + len).toString('ascii'));
    offset += len;
  }

  return parts.length > 0 ? parts.join('.') : null;
}

function formatIpv6(buf: Buffer): string {
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(buf.readUInt16BE(i).toString(16));
  }
  return parts.join(':');
}

function parsePcapNg(buffer: Buffer, filename: string): PcapAnalysisResult {
  // Simple PCAPNG block reader
  let offset = 0;
  let isLittleEndian = true;
  const packets: ParsedPacket[] = [];
  const protocolsCount: Record<string, number> = {};
  const conversationsMap = new Map<string, Conversation>();
  const findings: PcapAnalysisResult['findings'] = [];

  let packetIndex = 1;
  let totalBytes = 0;
  let firstTimestamp = 0;
  let lastTimestamp = 0;

  while (offset + 12 <= buffer.length && packetIndex <= 1000) {
    const blockType = buffer.readUInt32LE(offset);
    const blockLen = buffer.readUInt32LE(offset + 4);

    if (blockLen < 12 || offset + blockLen > buffer.length) {
      break;
    }

    if (blockType === 0x0a0d0d0a) {
      // Section Header Block, check byte order magic at offset + 8
      const bom = buffer.readUInt32LE(offset + 8);
      isLittleEndian = bom === 0x1a2b3c4d;
    } else if (blockType === 0x00000006) {
      // Enhanced Packet Block (EPB)
      // Interface ID (4), Timestamp High (4), Timestamp Low (4), Captured Packet Len (4), Original Packet Len (4)
      const tsHigh = buffer.readUInt32LE(offset + 12);
      const tsLow = buffer.readUInt32LE(offset + 16);
      const capLen = buffer.readUInt32LE(offset + 20);
      const origLen = buffer.readUInt32LE(offset + 24);

      totalBytes += origLen;
      const rawPacket = buffer.subarray(offset + 28, offset + 28 + capLen);

      const timeInSec = (tsHigh * 4294967296 + tsLow) / 1000000;
      if (packetIndex === 1) firstTimestamp = timeInSec;
      lastTimestamp = timeInSec;
      const relTime = (timeInSec - firstTimestamp).toFixed(4) + 's';

      const parsed = parsePacketData(rawPacket, 1, packetIndex, relTime);
      packets.push(parsed);
      protocolsCount[parsed.protocol] = (protocolsCount[parsed.protocol] || 0) + 1;

      if (parsed.source && parsed.destination && parsed.source !== 'Unknown') {
        const convKey = [parsed.source, parsed.destination].sort().join(' <-> ');
        const existing = conversationsMap.get(convKey);
        if (existing) {
          existing.packets += 1;
          existing.bytes += capLen;
        } else {
          conversationsMap.set(convKey, {
            endpointA: parsed.source,
            endpointB: parsed.destination,
            protocol: parsed.protocol,
            packets: 1,
            bytes: capLen,
          });
        }
      }

      if (parsed.isPlaintext && parsed.plaintextSnippet) {
        if (parsed.credentialsFound) {
          findings.push({
            type: 'critical',
            title: `Cleartext Credentials Exposed (${parsed.credentialsFound.type})`,
            description: `Authentication secrets detected in unencrypted transmission.`,
            packetId: parsed.id,
            details: parsed.credentialsFound.details,
          });
        }
      }

      packetIndex++;
    }

    offset += blockLen;
  }

  return {
    filename,
    format: 'PCAPNG',
    totalPackets: packets.length,
    totalBytes,
    durationSeconds: parseFloat(Math.max(0, lastTimestamp - firstTimestamp).toFixed(3)),
    protocols: protocolsCount,
    plaintextWarningsCount: findings.length,
    packets,
    conversations: Array.from(conversationsMap.values()).sort((a, b) => b.bytes - a.bytes).slice(0, 20),
    findings: findings.slice(0, 15),
  };
}

/**
 * Creates a valid synthetic educational PCAP capture buffer containing
 * a demonstration scenario (e.g. Plaintext HTTP Basic Auth, DNS lookup, and Port scan probe).
 */
export function generateDemoPcap(type: 'auth_sniffing' | 'dns_recon'): Buffer {
  const globalHeader = Buffer.alloc(24);
  globalHeader.writeUInt32BE(0xa1b2c3d4, 0); // magic
  globalHeader.writeUInt16BE(2, 4); // v_major
  globalHeader.writeUInt16BE(4, 6); // v_minor
  globalHeader.writeUInt32BE(0, 8); // timezone
  globalHeader.writeUInt32BE(0, 12); // sigfigs
  globalHeader.writeUInt32BE(65535, 16); // snaplen
  globalHeader.writeUInt32BE(1, 20); // LinkType Ethernet

  const packetBuffers: Buffer[] = [];

  function addPacket(sec: number, usec: number, frame: Buffer) {
    const pHeader = Buffer.alloc(16);
    pHeader.writeUInt32BE(sec, 0);
    pHeader.writeUInt32BE(usec, 4);
    pHeader.writeUInt32BE(frame.length, 8); // incl_len
    pHeader.writeUInt32BE(frame.length, 12); // orig_len
    packetBuffers.push(pHeader);
    packetBuffers.push(frame);
  }

  function createEthernetFrame(srcIp: [number, number, number, number], dstIp: [number, number, number, number], proto: number, transportData: Buffer): Buffer {
    const eth = Buffer.alloc(14);
    eth.writeUInt16BE(0x0800, 12); // IPv4

    const ip = Buffer.alloc(20);
    ip[0] = 0x45; // IPv4, 20 bytes
    ip.writeUInt16BE(20 + transportData.length, 2);
    ip[8] = 64; // TTL
    ip[9] = proto; // TCP=6, UDP=17
    ip.set(srcIp, 12);
    ip.set(dstIp, 16);

    return Buffer.concat([eth, ip, transportData]);
  }

  if (type === 'auth_sniffing') {
    // 1. TCP SYN
    const tcpSyn = Buffer.alloc(20);
    tcpSyn.writeUInt16BE(54321, 0);
    tcpSyn.writeUInt16BE(80, 2);
    tcpSyn[12] = 0x50;
    tcpSyn[13] = 0x02; // SYN
    addPacket(1720000000, 10000, createEthernetFrame([192, 168, 1, 105], [10, 0, 0, 50], 6, tcpSyn));

    // 2. TCP SYN-ACK
    const tcpSynAck = Buffer.alloc(20);
    tcpSynAck.writeUInt16BE(80, 0);
    tcpSynAck.writeUInt16BE(54321, 2);
    tcpSynAck[12] = 0x50;
    tcpSynAck[13] = 0x12; // SYN, ACK
    addPacket(1720000000, 14000, createEthernetFrame([10, 0, 0, 50], [192, 168, 1, 105], 6, tcpSynAck));

    // 3. HTTP Request with Basic Auth
    const httpPayload = Buffer.from(
      "GET /admin/dashboard HTTP/1.1\r\n" +
      "Host: internal-portal.corp.local\r\n" +
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n" +
      "Authorization: Basic YWRtaW46U3VwZXJTZWNyZXQyMDI2IQ==\r\n" +
      "Accept: text/html,application/xhtml+xml\r\n\r\n"
    );
    const tcpData = Buffer.alloc(20);
    tcpData.writeUInt16BE(54321, 0);
    tcpData.writeUInt16BE(80, 2);
    tcpData[12] = 0x50;
    tcpData[13] = 0x18; // PSH, ACK
    addPacket(1720000000, 22000, createEthernetFrame([192, 168, 1, 105], [10, 0, 0, 50], 6, Buffer.concat([tcpData, httpPayload])));

    // 4. HTTP 200 OK Response
    const httpResponse = Buffer.from(
      "HTTP/1.1 200 OK\r\n" +
      "Content-Type: text/html; charset=UTF-8\r\n" +
      "Server: Apache/2.4.41 (Ubuntu)\r\n" +
      "Set-Cookie: session_id=9f8e7d6c5b4a3; HttpOnly; SameSite=Lax\r\n\r\n" +
      "<h1>Welcome Administrator</h1><p>Privileged Console Active</p>"
    );
    const tcpResp = Buffer.alloc(20);
    tcpResp.writeUInt16BE(80, 0);
    tcpResp.writeUInt16BE(54321, 2);
    tcpResp[12] = 0x50;
    tcpResp[13] = 0x18; // PSH, ACK
    addPacket(1720000000, 31000, createEthernetFrame([10, 0, 0, 50], [192, 168, 1, 105], 6, Buffer.concat([tcpResp, httpResponse])));
  } else {
    // DNS Recon demo
    const dnsQueryPayload = Buffer.from([
      0x12, 0x34, // Transaction ID
      0x01, 0x00, // Standard query
      0x00, 0x01, // Questions: 1
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // domain: api.internal.corp.local
      0x03, 0x61, 0x70, 0x69, // api
      0x08, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, // internal
      0x04, 0x63, 0x6f, 0x72, 0x70, // corp
      0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, // local
      0x00,
      0x00, 0x01, // Type A
      0x00, 0x01  // Class IN
    ]);
    const udp = Buffer.alloc(8);
    udp.writeUInt16BE(49152, 0);
    udp.writeUInt16BE(53, 2);
    udp.writeUInt16BE(8 + dnsQueryPayload.length, 4);
    addPacket(1720000000, 15000, createEthernetFrame([192, 168, 1, 105], [8, 8, 8, 8], 17, Buffer.concat([udp, dnsQueryPayload])));
  }

  return Buffer.concat([globalHeader, ...packetBuffers]);
}
