// Copyright 2011 Timothy J Fontaine <tjfontaine@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the 'Software'), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE

// TODO: change the default UDP packet size that node-dns sends
//       from 4096 to conform to these:
//       - [requestor's payload size](https://tools.ietf.org/html/rfc6891#section-6.2.3)
//       - [responders's payload size](https://tools.ietf.org/html/rfc6891#section-6.2.4)

'use strict';

var consts = require('./consts'),
    BufferCursor = require('buffercursor'),
    BufferCursorOverflow = BufferCursor.BufferCursorOverflow,
    ipaddr = require('ipaddr.js'),
    assert = require('assert'),
    util = require('util');

function assertUndefined(val, msg) {
  assert(typeof val != 'undefined', msg);
}

function hasType(type) {
  return this.types.indexOf(type) !== -1;
}

var Packet = module.exports = function() {
  this.header = {
    id: 0,
    qr: 0,
    opcode: 0,
    aa: 0,
    tc: 0,
    rd: 1,
    ra: 0,
    res1: 0,
    ad: 0,
    cd: 0,
    rcode: 0
  };
  this.question = [];
  this.answer = [];
  this.authority = [];
  this.additional = [];
  this.edns_options = [];   // TODO: DEPRECATED! Use `.edns.options` instead!
  this.payload = undefined; // TODO: DEPRECATED! Use `.edns.payload` instead!
};

var LABEL_POINTER = exports.LABEL_POINTER = 0xC0;

var isPointer = exports.isPointer = function(len) {
  return (len & LABEL_POINTER) === LABEL_POINTER;
};

var nameUnpack = exports.nameUnpack = function(buff) {
  var len, comp, rawStart, rawEnd, end, pos, part, combine = '', raw;

  rawStart = buff.tell();
  len = buff.readUInt8();
  comp = false;
  end = buff.tell();
  rawEnd = buff.tell();

  while (len !== 0) {
    if (isPointer(len)) {
      len -= LABEL_POINTER;
      len = len << 8;
      pos = len + buff.readUInt8();
      rawStart = pos;
      if (!comp)
        end = buff.tell();
      buff.seek(pos);
      len = buff.readUInt8();
      comp = true;
      continue;
    }

    part = buff.toString('ascii', len);

    if (combine.length)
      combine = combine + '.' + part;
    else
      combine = part;

    len = buff.readUInt8();
    if(comp)
      rawEnd = buff.tell();

    if (!comp) {
      end = buff.tell();
      rawEnd = buff.tell();
    }
  }

  if(len === 0)
    combine += '.';

  // Return Raw Name Data
  buff.seek(rawStart);
  raw = new BufferCursor(new Buffer(rawEnd-rawStart));
  raw.copy(buff, rawStart, rawEnd);
  raw.seek(0);
  var rawBytes = raw.toByteArray();

  buff.seek(end);

  return {
    name: combine,
    raw: rawBytes
  };
};

var namePack = exports.namePack = function(str, buff, index, canonical) {
  var offset, dot, part;
  var isCanonical = canonical || false;

  if(str == ".") {
    buff.writeUInt8(0);
    return;
  }

  while (str) {
    if (index[str] && !isCanonical) {
      offset = (LABEL_POINTER << 8) + index[str];
      buff.writeUInt16BE(offset);
      break;
    } else {
      index[str] = buff.tell();
      dot = str.indexOf('.');
      if (dot > -1) {
        part = str.slice(0, dot);
        str = str.slice(dot + 1);
      } else {
        part = str;
        str = undefined;
      }
      buff.writeUInt8(part.length);
      buff.write(part, part.length, 'ascii');
    }
  }

  if (!str) {
    buff.writeUInt8(0);
  }
};

/* Handle TypeBitmap data types */
function parseTypeBitmap(buff) {
  var types = [];
  var lastbase = -1;
  while(!buff.eof()) {

    if((buff.length - buff.tell()) <  2) throw "invalid bitmap descriptor";

    var mapbase = buff.readUInt8();
    if(mapbase < lastbase) throw "invalid ordering";

    var maplength = buff.readUInt8();
    if(maplength > (buff.length - buff.tell())) throw "invalid bitmap";


    for(var i = 0; i < maplength; i++) {
      var current = buff.readUInt8();
      if(current === 0) continue;
      for(var j = 0; j < 8; j++) {
        if((current & (1 << (7-j))) === 0) continue;
        var typecode = mapbase * 256 + i*8 + j;
        types.push(typecode);
      }
    }
  }
  return types;
}

function writeTypeBitmap(buff, types) {
  if(types.length === 0) return;

  var mapbase = -1;
  var map = [];
  for(var i = 0; i < types.length; i++) {
    var t = types[i];
    var base = t >> 8;
    if (base !== mapbase) {
      if(map.length > 0) {
        mapToWire(buff, map, mapbase);
        map = [];
      }
      mapbase = base;
    }
    map.push(t);
    map.sort(function(a, b){return a-b});
  }
  mapToWire(buff, map, mapbase);
}

function mapToWire(buff, map, mapbase) {
  var arraymax = map[map.length - 1] & 0xFF;
  var arraylength = Math.floor(arraymax / 8) + 1;
  var array = Array.apply(null, new Array(arraylength)).map(Number.prototype.valueOf, 0);

  buff.writeUInt8(mapbase);
  buff.writeUInt8(arraylength);
  for(var i = 0; i < map.length; i++) {
    var typecode = map[i];
    array[Math.floor((typecode & 0xFF) / 8)] |= (1 << ( 7 - typecode % 8));
  }
  for(var j = 0; j < arraylength; j++) {
    buff.writeUInt8(array[j]);
  }
}

var
  WRITE_HEADER              = 100001,
  WRITE_TRUNCATE            = 100002,
  WRITE_QUESTION            = 100003,
  WRITE_RESOURCE_RECORD     = 100004,
  WRITE_RESOURCE_WRITE      = 100005,
  WRITE_RESOURCE_DONE       = 100006,
  WRITE_RESOURCE_END        = 100007,
  WRITE_EDNS                = 100008,
  WRITE_END                 = 100009,
  WRITE_A          = consts.NAME_TO_QTYPE.A,
  WRITE_AAAA       = consts.NAME_TO_QTYPE.AAAA,
  WRITE_NS         = consts.NAME_TO_QTYPE.NS,
  WRITE_CNAME      = consts.NAME_TO_QTYPE.CNAME,
  WRITE_PTR        = consts.NAME_TO_QTYPE.PTR,
  WRITE_SPF        = consts.NAME_TO_QTYPE.SPF,
  WRITE_MX         = consts.NAME_TO_QTYPE.MX,
  WRITE_SRV        = consts.NAME_TO_QTYPE.SRV,
  WRITE_TXT        = consts.NAME_TO_QTYPE.TXT,
  WRITE_SOA        = consts.NAME_TO_QTYPE.SOA,
  WRITE_OPT        = consts.NAME_TO_QTYPE.OPT,
  WRITE_NAPTR      = consts.NAME_TO_QTYPE.NAPTR,
  WRITE_DS         = consts.NAME_TO_QTYPE.DS,
  WRITE_RRSIG      = consts.NAME_TO_QTYPE.RRSIG,
  WRITE_DNSKEY     = consts.NAME_TO_QTYPE.DNSKEY,
  WRITE_NSEC3      = consts.NAME_TO_QTYPE.NSEC3,
  WRITE_NSEC3PARAM = consts.NAME_TO_QTYPE.NSEC3PARAM,
  WRITE_TLSA       = consts.NAME_TO_QTYPE.TLSA;

var writeHeader = Packet.writeHeader = function(buff, packet) {
  assert(packet.header, 'Packet requires "header"');
  buff.writeUInt16BE(packet.header.id & 0xFFFF);
  var val = 0;
  val += (packet.header.qr << 15) & 0x8000;
  val += (packet.header.opcode << 11) & 0x7800;
  val += (packet.header.aa << 10) & 0x400;
  val += (packet.header.tc << 9) & 0x200;
  val += (packet.header.rd << 8) & 0x100;
  val += (packet.header.ra << 7) & 0x80;
  val += (packet.header.res1 << 6) & 0x40;
  val += (packet.header.ad << 5) & 0x20;
  val += (packet.header.cd << 4) & 0x10;
  val += packet.header.rcode & 0xF;
  buff.writeUInt16BE(val & 0xFFFF);
  assert(packet.question.length == 1, 'DNS requires one question');
  // aren't used
  buff.writeUInt16BE(1);
  // answer offset 6
  buff.writeUInt16BE(packet.answer.length & 0xFFFF);
  // authority offset 8
  buff.writeUInt16BE(packet.authority.length & 0xFFFF);
  // additional offset 10
  buff.writeUInt16BE(packet.additional.length & 0xFFFF);
  return WRITE_QUESTION;
};

var writeTruncate = Packet.writeTruncate = function(buff, packet, section, val) {
  // XXX FIXME TODO truncation is currently done wrong.
  // Quote rfc2181 section 9
  // The TC bit should not be set merely because some extra information
  // could have been included, but there was insufficient room.  This
  // includes the results of additional section processing.  In such cases
  // the entire RRSet that will not fit in the response should be omitted,
  // and the reply sent as is, with the TC bit clear.  If the recipient of
  // the reply needs the omitted data, it can construct a query for that
  // data and send that separately.
  //
  // TODO IOW only set TC if we hit it in ANSWERS otherwise make sure an
  // entire RRSet is removed during a truncation.
  var pos;

  buff.seek(2);
  val = buff.readUInt16BE();
  val |= (1 << 9) & 0x200;
  buff.seek(2);
  buff.writeUInt16BE(val);
  switch (section) {
    case 'answer':
      pos = 6;
      // seek to authority and clear it and additional out
      buff.seek(8);
      buff.writeUInt16BE(0);
      buff.writeUInt16BE(0);
      break;
    case 'authority':
      pos = 8;
      // seek to additional and clear it out
      buff.seek(10);
      buff.writeUInt16BE(0);
      break;
    case 'additional':
      pos = 10;
      break;
  }
  buff.seek(pos);
  buff.writeUInt16BE(count - 1); // TODO: count not defined!
  buff.seek(last_resource);      // TODO: last_resource not defined!
  return WRITE_END;
};

var writeQuestion = Packet.writeQuestion = function(buff, val, label_index) {
  assert(val, 'Packet requires a question');
  assertUndefined(val.name, 'Question requires a "name"');
  assertUndefined(val.type, 'Question requires a "type"');
  assertUndefined(val.class, 'Questionn requires a "class"');
  namePack(val.name, buff, label_index);
  buff.writeUInt16BE(val.type & 0xFFFF);
  buff.writeUInt16BE(val.class & 0xFFFF);
  return WRITE_RESOURCE_RECORD;
};

var writeResource = Packet.writeResource = function(buff, val, label_index, rdata) {
  assert(val, 'Resource must be defined');
  assertUndefined(val.name, 'Resource record requires "name"');
  assertUndefined(val.type, 'Resource record requires "type"');
  assertUndefined(val.class, 'Resource record requires "class"');
  assertUndefined(val.ttl, 'Resource record requires "ttl"');
  namePack(val.name, buff, label_index);
  buff.writeUInt16BE(val.type & 0xFFFF);
  buff.writeUInt16BE(val.class & 0xFFFF);
  buff.writeUInt32BE(val.ttl & 0xFFFFFFFF);
  rdata.pos = buff.tell();
  buff.writeUInt16BE(0); // if there is rdata, then this value will be updated
                         // to the correct value by 'writeResourceDone'
  return val.type;
};

var writeResourceDone = Packet.writeResourceDone = function(buff, rdata) {
  var pos = buff.tell();
  buff.seek(rdata.pos);
  buff.writeUInt16BE(pos - rdata.pos - 2);
  buff.seek(pos);
  return WRITE_RESOURCE_RECORD;
};

var writeIp = Packet.writeIp = function(buff, val) {
  //TODO XXX FIXME -- assert that address is of proper type
  assertUndefined(val.address, 'A/AAAA record requires "address"');
  val = ipaddr.parse(val.address).toByteArray();
  val.forEach(function(b) {
    buff.writeUInt8(b);
  });
  return WRITE_RESOURCE_DONE;
};

var writeCname = Packet.writeCname = function(buff, val, label_index) {
  assertUndefined(val.data, 'NS/CNAME/PTR record requires "data"');
  namePack(val.data, buff, label_index);
  return WRITE_RESOURCE_DONE;
};

// For <character-string> see: http://tools.ietf.org/html/rfc1035#section-3.3
// For TXT: http://tools.ietf.org/html/rfc1035#section-3.3.14
var writeTxt = Packet.writeTxt = function(buff, val) {
  //TODO XXX FIXME -- split on max char string and loop
  assertUndefined(val.data, 'TXT record requires "data"');
  for (var i=0,len=val.data.length; i<len; i++) {
    var dataLen = Buffer.byteLength(val.data[i], 'utf8');
    buff.writeUInt8(dataLen);
    buff.write(val.data[i], dataLen, 'utf8');
  }
  return WRITE_RESOURCE_DONE;
};

var writeMx = Packet.writeMx = function(buff, val, label_index) {
  assertUndefined(val.priority, 'MX record requires "priority"');
  assertUndefined(val.exchange, 'MX record requires "exchange"');
  buff.writeUInt16BE(val.priority & 0xFFFF);
  namePack(val.exchange, buff, label_index);
  return WRITE_RESOURCE_DONE;
};

// SRV: https://tools.ietf.org/html/rfc2782
// TODO: SRV fixture failing for '_xmpp-server._tcp.gmail.com.srv.js'
var writeSrv = Packet.writeSrv = function(buff, val, label_index) {
  assertUndefined(val.priority, 'SRV record requires "priority"');
  assertUndefined(val.weight, 'SRV record requires "weight"');
  assertUndefined(val.port, 'SRV record requires "port"');
  assertUndefined(val.target, 'SRV record requires "target"');
  buff.writeUInt16BE(val.priority & 0xFFFF);
  buff.writeUInt16BE(val.weight & 0xFFFF);
  buff.writeUInt16BE(val.port & 0xFFFF);
  namePack(val.target, buff, label_index);
  return WRITE_RESOURCE_DONE;
};

var writeSoa = Packet.writeSoa = function(buff, val, label_index, canonical) {
  assertUndefined(val.primary, 'SOA record requires "primary"');
  assertUndefined(val.admin, 'SOA record requires "admin"');
  assertUndefined(val.serial, 'SOA record requires "serial"');
  assertUndefined(val.refresh, 'SOA record requires "refresh"');
  assertUndefined(val.retry, 'SOA record requires "retry"');
  assertUndefined(val.expiration, 'SOA record requires "expiration"');
  assertUndefined(val.minimum, 'SOA record requires "minimum"');
  namePack(val.primary, buff, label_index, canonical);
  namePack(val.admin, buff, label_index, canonical);
  buff.writeUInt32BE(val.serial & 0xFFFFFFFF);
  buff.writeInt32BE(val.refresh & 0xFFFFFFFF);
  buff.writeInt32BE(val.retry & 0xFFFFFFFF);
  buff.writeInt32BE(val.expiration & 0xFFFFFFFF);
  buff.writeInt32BE(val.minimum & 0xFFFFFFFF);
  return WRITE_RESOURCE_DONE;
};

// http://tools.ietf.org/html/rfc3403#section-4.1
var writeNaptr = Packet.writeNaptr = function(buff, val, label_index) {
  assertUndefined(val.order, 'NAPTR record requires "order"');
  assertUndefined(val.preference, 'NAPTR record requires "preference"');
  assertUndefined(val.flags, 'NAPTR record requires "flags"');
  assertUndefined(val.service, 'NAPTR record requires "service"');
  assertUndefined(val.regexp, 'NAPTR record requires "regexp"');
  assertUndefined(val.replacement, 'NAPTR record requires "replacement"');
  buff.writeUInt16BE(val.order & 0xFFFF);
  buff.writeUInt16BE(val.preference & 0xFFFF);
  buff.writeUInt8(val.flags.length);
  buff.write(val.flags, val.flags.length, 'ascii');
  buff.writeUInt8(val.service.length);
  buff.write(val.service, val.service.length, 'ascii');
  buff.writeUInt8(val.regexp.length);
  buff.write(val.regexp, val.regexp.length, 'ascii');
  namePack(val.replacement, buff, label_index);
  return WRITE_RESOURCE_DONE;
};

// https://tools.ietf.org/html/rfc6698
var writeTlsa = Packet.writeTlsa = function(buff, val) {
  assertUndefined(val.usage, 'TLSA record requires "usage"');
  assertUndefined(val.selector, 'TLSA record requires "selector"');
  assertUndefined(val.matchingtype, 'TLSA record requires "matchingtype"');
  assertUndefined(val.buff, 'TLSA record requires "buff"');
  buff.writeUInt8(val.usage);
  buff.writeUInt8(val.selector);
  buff.writeUInt8(val.matchingtype);
  buff.copy(val.buff);
  return WRITE_RESOURCE_DONE;
};

var writeRrsig = Packet.writeRrsig = function(buff, val, label_index) {
  assertUndefined(val.typeCovered, 'RRSIG record requires "typeCovered');
  assertUndefined(val.algorithm, 'RRSIG record requires "algorithm');
  assertUndefined(val.labels, 'RRSIG record requires "labels');
  assertUndefined(val.originalTtl, 'RRSIG record requires "originalTtl');
  assertUndefined(val.signatureExpiration, 'RRSIG record requires "signatureExpiration');
  assertUndefined(val.signatureInception, 'RRSIG record requires "signatureInception');
  assertUndefined(val.keytag, 'RRSIG record requires "keytag');
  assertUndefined(val.signerName, 'RRSIG record requires "signerName');
  assertUndefined(val.signature, 'RRSIG record requires "signature');

  buff.writeUInt16BE(val.typeCovered);
  buff.writeUInt8(val.algorithm);
  buff.writeUInt8(val.labels);
  buff.writeUInt32BE(val.originalTtl);
  buff.writeUInt32BE(val.signatureExpiration.getTime() / 1000);
  buff.writeUInt32BE(val.signatureInception.getTime() / 1000);
  buff.writeUInt16BE(val.keytag);
  namePack(val.signerName, buff, label_index);
  buff.copy(val.signature);

  return WRITE_RESOURCE_DONE;
};

var writeDs = Packet.writeDs = function(buff, val) {
  assertUndefined(val.keytag, 'DS record requires "keytag"');
  assertUndefined(val.algorithm, 'DS record requires "algorithm');
  assertUndefined(val.digestType, 'DS record requires "digestType');
  assertUndefined(val.digest, 'DS record requires "digest');

  buff.writeUInt16BE(val.keytag & 0xFFFF);
  buff.writeUInt8(val.algorithm);
  buff.writeUInt8(val.digestType);
  buff.copy(val.digest);

  return WRITE_RESOURCE_DONE;
};

var writeDnskey = Packet.writeDnskey = function(buff, val) {
  assertUndefined(val.flags, 'DNSKEY record requires "keytag"');
  assertUndefined(val.protocol, 'DNSKEY record requires "protocol"');
  assertUndefined(val.algorithm, 'DNSKEY record requires "algorithm"');
  assertUndefined(val.publicKey, 'DNSKEY record requires "publicKey"');

  buff.writeUInt16BE(val.flags);
  buff.writeUInt8(val.protocol);
  buff.writeUInt8(val.algorithm);
  buff.copy(val.publicKey);

  return WRITE_RESOURCE_DONE;
};

var writeNsec = Packet.writeNsec = function (buff, val, label_index) {
  assertUndefined(val.next, 'NSEC record requires "next"');
  assertUndefined(val.types, 'NSEC record requires "types');
  namePack(val.next, buff, label_index, true);
  writeTypeBitmap(buff, val.types);
  return WRITE_RESOURCE_DONE;
};

var writeNsec3 = Packet.writeNsec3 = function(buff, val, label_index) {
  assertUndefined(val.hashAlgorithm, 'NSEC3 record requires "hashAlgorithm"');
  assertUndefined(val.flags, 'NSEC3 record requires "flags"');
  assertUndefined(val.iterations, 'NSEC3 record requires "iterations"');
  assertUndefined(val.salt, 'NSEC3 record requires "salt"');
  assertUndefined(val.nextHashedOwnerName, 'NSEC3 record requires "nextHashedOwnerName"');

  buff.writeUInt8(val.hashAlgorithm);
  buff.writeUInt8(val.flags);
  buff.writeUInt16BE(val.iterations);

  buff.writeUInt8(val.salt.length);
  buff.copy(val.salt);

  buff.writeUInt8(val.nextHashedOwnerName.length);
  buff.copy(val.nextHashedOwnerName);
  writeTypeBitmap(buff, val.types);

  return WRITE_RESOURCE_DONE;
};

var writeNsec3Param = Packet.writeNsec3Param = function(buff, val, label_index) {
  assertUndefined(val.hashAlgorithm, 'NSEC3PARAM record requires "hashAlgorithm"');
  assertUndefined(val.flags, 'NSEC3PARAM record requires "flags"');
  assertUndefined(val.iterations, 'NSEC3PARAM record requires "iterations"');
  assertUndefined(val.salt, 'NSEC3PARAM record requires "salt"');

  buff.writeUInt8(val.hashAlgorithm);
  buff.writeUInt8(val.flags);
  buff.writeUInt16BE(val.iterations);
  namePack(val.salt, buff, label_index);

  return WRITE_RESOURCE_DONE;
};

function makeEdns(packet) {
  packet.edns = {
    name: '',
    type: consts.NAME_TO_QTYPE.OPT,
    class: packet.payload,
    options: [],
    ttl: 0
  };
  packet.edns_options = packet.edns.options; // TODO: 'edns_options' is DEPRECATED!

  // Handle DNSSEC Request
  if(packet.do) {
    packet.edns.ttl = 0x8000;
  }
  packet.additional.push(packet.edns);
  return WRITE_HEADER;
}

var writeOpt = Packet.writeOpt = function(buff, val) {
  var opt;
  for (var i=0, len=val.options.length; i<len; i++) {
    opt = val.options[i];
    buff.writeUInt16BE(opt.code);
    buff.writeUInt16BE(opt.data.length);
    buff.copy(opt.data);
  }
  return WRITE_RESOURCE_DONE;
};

Packet.write = function(buff, packet) {
  var state = WRITE_HEADER,
      val,
      section,
      count,
      rdata,
      last_resource,
      label_index = {};

  buff = new BufferCursor(buff);

  // the existence of 'edns' in a packet indicates that a proper OPT record exists
  // in 'additional' and that all of the other fields in packet (that are parsed by
  // 'parseOpt') are properly set. If it does not exist, we assume that the user
  // is requesting that we create one for them.
  if (typeof packet.edns_version !== 'undefined' && typeof packet.edns === "undefined")
    state = makeEdns(packet);

  // TODO: this is unnecessarily inefficient. rewrite this using a
  //       function table instead. (same for Packet.parse too).
  while (true) {
    try {
      switch (state) {
        case WRITE_HEADER:
          state = writeHeader(buff, packet);
          break;
        case WRITE_TRUNCATE:
          state = writeTruncate(buff, packet, section, last_resource);
          break;
        case WRITE_QUESTION:
          state = writeQuestion(buff, packet.question[0], label_index);
          section = 'answer';
          count = 0;
          break;
        case WRITE_RESOURCE_RECORD:
          last_resource = buff.tell();
          if (packet[section].length == count) {
            switch (section) {
              case 'answer':
                section = 'authority';
                state = WRITE_RESOURCE_RECORD;
                break;
              case 'authority':
                section = 'additional';
                state = WRITE_RESOURCE_RECORD;
                break;
              case 'additional':
                state = WRITE_END;
                break;
            }
            count = 0;
          } else {
            state = WRITE_RESOURCE_WRITE;
          }
          break;
        case WRITE_RESOURCE_WRITE:
          rdata = {};
          val = packet[section][count];
          state = writeResource(buff, val, label_index, rdata);
          break;
        case WRITE_RESOURCE_DONE:
          count += 1;
          state = writeResourceDone(buff, rdata);
          break;
        case WRITE_A:
        case WRITE_AAAA:
          state = writeIp(buff, val);
          break;
        case WRITE_NS:
        case WRITE_CNAME:
        case WRITE_PTR:
          state = writeCname(buff, val, label_index);
          break;
        case WRITE_SPF:
        case WRITE_TXT:
          state = writeTxt(buff, val);
          break;
        case WRITE_MX:
          state = writeMx(buff, val, label_index);
          break;
        case WRITE_SRV:
          state = writeSrv(buff, val, label_index);
          break;
        case WRITE_SOA:
          state = writeSoa(buff, val, label_index);
          break;
        case WRITE_OPT:
          state = writeOpt(buff, val);
          break;
        case WRITE_NAPTR:
          state = writeNaptr(buff, val, label_index);
          break;
        case WRITE_DS:
          state = writeDs(buff, val);
          break;
        case WRITE_RRSIG:
          state = writeRrsig(buff, val, label_index);
          break;
        case WRITE_DNSKEY:
          state = writeDnskey(buff, val);
          break;
        case WRITE_NSEC3:
          state = writeNsec3(buff, val, label_index);
          break;
        case WRITE_NSEC3PARAM:
          state = writeNsec3Param(buff, val, label_index);
          break;
        case WRITE_TLSA:
          state = writeTlsa(buff, val);
          break;
        case WRITE_END:
          return buff.tell();
        default:
          if (typeof val.data !== 'object')
            throw new Error('Packet.write Unknown State: ' + state);
          // write unhandled RR type
          buff.copy(val.data);
          state = WRITE_RESOURCE_DONE;
      }
    } catch (e) {
      if (e instanceof BufferCursorOverflow) {
        state = WRITE_TRUNCATE;
      } else {
        throw e;
      }
    }
  }
};

function parseHeader(msg, packet) {
  packet.header.id = msg.readUInt16BE();
  var val = msg.readUInt16BE();
  packet.header.qr = (val & 0x8000) >> 15;
  packet.header.opcode = (val & 0x7800) >> 11;
  packet.header.aa = (val & 0x400) >> 10;
  packet.header.tc = (val & 0x200) >> 9;
  packet.header.rd = (val & 0x100) >> 8;
  packet.header.ra = (val & 0x80) >> 7;
  packet.header.res1 = (val & 0x40) >> 6;
  packet.header.ad = (val & 0x20) >> 5;
  packet.header.cd = (val & 0x10) >> 4;
  packet.header.rcode = (val & 0xF);
  packet.question = new Array(msg.readUInt16BE());
  packet.answer = new Array(msg.readUInt16BE());
  packet.authority = new Array(msg.readUInt16BE());
  packet.additional = new Array(msg.readUInt16BE());
  return PARSE_QUESTION;
}

function parseQuestion(msg, packet) {
  var val = {};
  var nameret = nameUnpack(msg);
  val.name = nameret.name;
  val.nameRaw = nameret.raw;
  val.type = msg.readUInt16BE();
  val.class = msg.readUInt16BE();
  packet.question[0] = val;
  assert(packet.question.length === 1);
  // TODO handle qdcount > 1 in practice no one sends this
  return PARSE_RESOURCE_RECORD;
}

function parseRR(msg, val, rdata) {
  var nameret = nameUnpack(msg);
  val.name = nameret.name;
  val.nameRaw = nameret.raw;
  val.type = msg.readUInt16BE();
  val.class = msg.readUInt16BE();
  val.ttl = msg.readUInt32BE();
  rdata.len = msg.readUInt16BE();
  return val.type;
}

function parseA(val, msg) {
  val.address = '' +
      msg.readUInt8() +
      '.' + msg.readUInt8() +
      '.' + msg.readUInt8() +
      '.' + msg.readUInt8();
  return PARSE_RESOURCE_DONE;
}

function parseAAAA(val, msg) {
  var address = '';
  var compressed = false;

  for (var i = 0; i < 8; i++) {
    if (i > 0) address += ':';
    // TODO zero compression
    address += msg.readUInt16BE().toString(16);
  }
  val.address = address;
  return PARSE_RESOURCE_DONE;
}

function parseCname(val, msg) {
  var nameret = nameUnpack(msg);
  val.data = nameret.name;
  val.dataRaw = nameret.raw;
  return PARSE_RESOURCE_DONE;
}

function parseTxt(val, msg, rdata) {
  val.data = [];
  var end = msg.tell() + rdata.len;
  while (msg.tell() != end) {
    var len = msg.readUInt8();
    val.data.push(msg.toString('utf8', len));
  }
  return PARSE_RESOURCE_DONE;
}

function parseMx(val, msg, rdata) {
  val.priority = msg.readUInt16BE();
  var nameret = nameUnpack(msg);
  val.exchange = nameret.name;
  val.exchangeRaw = nameret.raw;
  return PARSE_RESOURCE_DONE;
}

// TODO: SRV fixture failing for '_xmpp-server._tcp.gmail.com.srv.js'
//       https://tools.ietf.org/html/rfc2782
function parseSrv(val, msg) {
  val.priority = msg.readUInt16BE();
  val.weight = msg.readUInt16BE();
  val.port = msg.readUInt16BE();
  var nameret = nameUnpack(msg);
  val.target = nameret.name;
  val.targetRaw = nameret.raw;
  return PARSE_RESOURCE_DONE;
}

function parseSoa(val, msg) {
  var nameret = nameUnpack(msg);
  val.primary = nameret.name;
  val.primaryRaw = nameret.raw;

  nameret = nameUnpack(msg);
  val.admin = nameret.name;
  val.adminRaw = nameret.raw;

  val.serial = msg.readUInt32BE();
  val.refresh = msg.readInt32BE();
  val.retry = msg.readInt32BE();
  val.expiration = msg.readInt32BE();
  val.minimum = msg.readInt32BE();
  return PARSE_RESOURCE_DONE;
}

// http://tools.ietf.org/html/rfc3403#section-4.1
function parseNaptr(val, msg) {
  val.order = msg.readUInt16BE();
  val.preference = msg.readUInt16BE();
  var len = msg.readUInt8();
  val.flags = msg.toString('ascii', len);
  len = msg.readUInt8();
  val.service = msg.toString('ascii', len);
  len = msg.readUInt8();
  val.regexp = msg.toString('ascii', len);

  var nameret = nameUnpack(msg);
  val.replacement = nameret.name;
  val.replacementRaw = nameret.raw;
  return PARSE_RESOURCE_DONE;
}

function parseTlsa(val, msg, rdata) {
  val.usage = msg.readUInt8();
  val.selector = msg.readUInt8();
  val.matchingtype = msg.readUInt8();
  val.buff = msg.slice(rdata.len - 3).buffer; // 3 because of the 3 UInt8s above.
  return PARSE_RESOURCE_DONE;
}

// https://tools.ietf.org/html/rfc6891#section-6.1.2
// https://tools.ietf.org/html/rfc2671#section-4.4
//       - [payload size selection](https://tools.ietf.org/html/rfc6891#section-6.2.5)
function parseOpt(val, msg, rdata, packet) {
  // assert first entry in additional
  rdata.buf = msg.slice(rdata.len);

  val.rcode = ((val.ttl & 0xFF000000) >> 20) + packet.header.rcode;
  val.version = (val.ttl >> 16) & 0xFF;
  val.do = (val.ttl >> 15) & 1;
  val.z = val.ttl & 0x7F;
  val.options = [];

  packet.edns = val;
  packet.edns_version = val.version; // TODO: return BADVERS for unsupported version! (Section 6.1.3)

  // !! BEGIN DEPRECATION NOTICE !!
  // THESE FIELDS MAY BE REMOVED IN THE FUTURE!
  packet.edns_options = val.options;
  packet.payload = val.class;
  // !! END DEPRECATION NOTICE !!

  while (!rdata.buf.eof()) {
    val.options.push({
      code: rdata.buf.readUInt16BE(),
      data: rdata.buf.slice(rdata.buf.readUInt16BE()).buffer
    });
  }
  return PARSE_RESOURCE_DONE;
}

function parseDs(val, msg, rdata) {
  var startPos = msg.tell();
  val.keytag = msg.readUInt16BE();
  val.algorithm = msg.readUInt8();
  val.digestType = msg.readUInt8();
  val.digest = msg.slice(rdata.len - (msg.tell() - startPos));
  return PARSE_RESOURCE_DONE;
}

function parseRrsig(val, msg, rdata) {
  var startPos = msg.tell();
  val.typeCovered = msg.readUInt16BE();
  val.algorithm = msg.readUInt8();
  val.labels = msg.readUInt8();
  val.originalTtl = msg.readUInt32BE();
  val.signatureExpiration = new Date(msg.readUInt32BE() * 1000);
  val.signatureInception = new Date(msg.readUInt32BE() * 1000);
  val.keytag = msg.readUInt16BE();

  var nameret = nameUnpack(msg);
  val.signerName = nameret.name;
  val.signerNameRaw = nameret.raw;

  val.signature = msg.slice(rdata.len - (msg.tell() - startPos));
  return PARSE_RESOURCE_DONE;
}

function parseDnskey(val, msg, rdata) {
  var startPos = msg.tell();
  val.flags = msg.readUInt16BE();
  val.protocol = msg.readUInt8();
  val.algorithm = msg.readUInt8();
  val.publicKey = msg.slice(rdata.len - (msg.tell() - startPos));
  return PARSE_RESOURCE_DONE;
}

function parseNsec(val, msg, rdata) {
  var startPos = msg.tell();
  var nameret = nameUnpack(msg);
  val.next = nameret.name;
  val.nextRaw = nameret.raw;
  val.types = parseTypeBitmap(msg.slice(startPos + rdata.len - msg.tell()));

  val.hasType = hasType;
  return PARSE_RESOURCE_DONE;
}

function parseNsec3(val, msg, rdata) {
  var startPos = msg.tell();

  val.hashAlgorithm = msg.readUInt8();
  val.flags = msg.readUInt8();
  val.iterations = msg.readUInt16BE();

  var saltLen = msg.readUInt8();
  val.salt = msg.slice(saltLen);

  var hashLen = msg.readUInt8();
  val.nextHashedOwnerName = msg.slice(hashLen);

  val.types = parseTypeBitmap(msg.slice(startPos + rdata.len - msg.tell()));

  val.hasType = hasType;
  return PARSE_RESOURCE_DONE;
}

function parseNsec3param(val, msg) {
  val.hashAlgorithm = msg.readUInt8();
  val.flags = msg.readUInt8();
  val.iterations = msg.readUInt16BE();

  var nameret = nameUnpack(msg);
  val.salt = nameret.name;
  val.saltRaw = nameret.raw;
}

var
  PARSE_HEADER          = 100000,
  PARSE_QUESTION        = 100001,
  PARSE_RESOURCE_RECORD = 100002,
  PARSE_RR_UNPACK       = 100003,
  PARSE_RESOURCE_DONE   = 100004,
  PARSE_END             = 100005,
  PARSE_A          = consts.NAME_TO_QTYPE.A,
  PARSE_NS         = consts.NAME_TO_QTYPE.NS,
  PARSE_CNAME      = consts.NAME_TO_QTYPE.CNAME,
  PARSE_SOA        = consts.NAME_TO_QTYPE.SOA,
  PARSE_PTR        = consts.NAME_TO_QTYPE.PTR,
  PARSE_MX         = consts.NAME_TO_QTYPE.MX,
  PARSE_TXT        = consts.NAME_TO_QTYPE.TXT,
  PARSE_AAAA       = consts.NAME_TO_QTYPE.AAAA,
  PARSE_SRV        = consts.NAME_TO_QTYPE.SRV,
  PARSE_NAPTR      = consts.NAME_TO_QTYPE.NAPTR,
  PARSE_OPT        = consts.NAME_TO_QTYPE.OPT,
  PARSE_DS         = consts.NAME_TO_QTYPE.DS,
  PARSE_RRSIG      = consts.NAME_TO_QTYPE.RRSIG,
  PARSE_DNSKEY     = consts.NAME_TO_QTYPE.DNSKEY,
  PARSE_NSEC       = consts.NAME_TO_QTYPE.NSEC,
  PARSE_NSEC3      = consts.NAME_TO_QTYPE.NSEC3,
  PARSE_NSEC3PARAM = consts.NAME_TO_QTYPE.NSEC3PARAM,
  PARSE_SPF        = consts.NAME_TO_QTYPE.SPF,
  PARSE_TLSA       = consts.NAME_TO_QTYPE.TLSA;


Packet.parse = function(msg) {
  var state,
      pos,
      val,
      rdata,
      section,
      count;

  var packet = new Packet();

  pos = 0;
  state = PARSE_HEADER;

  msg = new BufferCursor(msg);

  while (true) {
    switch (state) {
      case PARSE_HEADER:
        state = parseHeader(msg, packet);
        break;
      case PARSE_QUESTION:
        state = parseQuestion(msg, packet);
        section = 'answer';
        count = 0;
        break;
      case PARSE_RESOURCE_RECORD:
        // console.log('PARSE_RESOURCE_RECORD: count = %d, %s.len = %d', count, section, packet[section].length);
        if (count === packet[section].length) {
          switch (section) {
            case 'answer':
              section = 'authority';
              count = 0;
              break;
            case 'authority':
              section = 'additional';
              count = 0;
              break;
            case 'additional':
              state = PARSE_END;
              break;
          }
        } else {
          state = PARSE_RR_UNPACK;
        }
        break;
      case PARSE_RR_UNPACK:
        val = {};
        rdata = {};
        state = parseRR(msg, val, rdata);
        break;
      case PARSE_RESOURCE_DONE:
        packet[section][count++] = val;
        state = PARSE_RESOURCE_RECORD;
        break;
      case PARSE_A:
        state = parseA(val, msg);
        break;
      case PARSE_AAAA:
        state = parseAAAA(val, msg);
        break;
      case PARSE_NS:
      case PARSE_CNAME:
      case PARSE_PTR:
        state = parseCname(val, msg);
        break;
      case PARSE_SPF:
      case PARSE_TXT:
        state = parseTxt(val, msg, rdata);
        break;
      case PARSE_MX:
        state = parseMx(val, msg);
        break;
      case PARSE_SRV:
        state = parseSrv(val, msg);
        break;
      case PARSE_SOA:
        state = parseSoa(val, msg);
        break;
      case PARSE_OPT:
        state = parseOpt(val, msg, rdata, packet);
        break;
      case PARSE_NAPTR:
        state = parseNaptr(val, msg);
        break;
      case PARSE_DS:
        state = parseDs(val, msg, rdata);
        break;
      case PARSE_RRSIG:
        state = parseRrsig(val, msg, rdata);
        break;
      case PARSE_DNSKEY:
        state = parseDnskey(val, msg, rdata);
        break;
      case PARSE_NSEC:
        state = parseNsec(val, msg, rdata);
        break;
      case PARSE_NSEC3:
        state = parseNsec3(val, msg, rdata);
        break;
      case PARSE_NSEC3PARAM:
        state = parseNsec3param(val, msg);
        break;
      case PARSE_TLSA:
        state = parseTlsa(val, msg, rdata);
        break;
      case PARSE_END:
        return packet;
      default:
        //console.log(state, val);
        val.data = msg.slice(rdata.len);
        state = PARSE_RESOURCE_DONE;
        break;
    }
  }
};

var buildDnssecRequestPacket = function (opts) {

  var qtype;

  qtype = opts.type || consts.NAME_TO_QTYPE.A;
  if (typeof(qtype) === 'string' || qtype instanceof String)
    qtype = consts.nameToQtype(qtype.toUpperCase());

  if (!qtype || typeof(qtype) !== 'number')
    throw new Error("Question type must be defined and be valid");

  return {
    answer: [],
    authority: [],
    additional: [],
    do: true,
    edns_options: [],
    edns_version: 0,
    header: {
      id: 4326,
      rd: 1
    },
    payload: 4096,
    question: [{
      name: opts.name,
      type: qtype,
      class: consts.NAME_TO_QCLASS.IN
    }],
    try_edns: true
  }
};