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
    res2: 0,
    res3: 0,
    rcode: 0
  };
  this.question = undefined;
  this.answer = undefined;
  this.authority = undefined;
  this.additional = undefined;
  this.edns_options = [];
  this.payload = undefined;
};

var LABEL_POINTER = 0xC0;

var isPointer = function(len) {
  return (len & LABEL_POINTER) === LABEL_POINTER;
};

var nameUnpack = function(buff) {
  var len, comp, end, pos, part, combine = '';

  len = buff.readUInt8();
  comp = false;

  while (len !== 0) {
    if (isPointer(len)) {
      len -= LABEL_POINTER;
      len = len << 8;
      pos = len + buff.readUInt8();
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

    if (!comp)
      end = buff.tell();
  }

  buff.seek(end);

  return combine;
};

var name_pack = function(str, buff, index) {
  var offset, dot, part;

  while (str) {
    if (index[str]) {
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

var
  WRITE_HEADER              = 100001,
  WRITE_TRUNCATE            = 100002,
  WRITE_NAME_PACK           = 100003,
  WRITE_QUESTION            = 100004,
  WRITE_QUESTION_NEXT       = 100005,
  WRITE_RESOURCE_RECORD     = 100006,
  WRITE_RESOURCE_WRITE      = 100007,
  WRITE_RESOURCE_WRITE_NEXT = 100008,
  WRITE_RESOURCE_DONE       = 100009,
  WRITE_RESOURCE_END        = 100010,
  WRITE_SOA_NEXT            = 100011,
  WRITE_SOA_ADMIN           = 100012,
  WRITE_EDNS                = 100013,
  WRITE_END                 = 100014,
  WRITE_A     = consts.NAME_TO_QTYPE.A,
  WRITE_AAAA  = consts.NAME_TO_QTYPE.AAAA,
  WRITE_NS    = consts.NAME_TO_QTYPE.NS,
  WRITE_CNAME = consts.NAME_TO_QTYPE.CNAME,
  WRITE_PTR   = consts.NAME_TO_QTYPE.PTR,
  WRITE_SPF   = consts.NAME_TO_QTYPE.SPF,
  WRITE_MX    = consts.NAME_TO_QTYPE.MX,
  WRITE_SRV   = consts.NAME_TO_QTYPE.SRV,
  WRITE_TXT   = consts.NAME_TO_QTYPE.TXT,
  WRITE_SOA   = consts.NAME_TO_QTYPE.SOA,
  WRITE_OPT   = consts.NAME_TO_QTYPE.OPT,
  WRITE_NAPTR = consts.NAME_TO_QTYPE.NAPTR;

Packet.write = function(buff, packet) {
  var state,
      next,
      name,
      val,
      section,
      count,
      pos,
      rdata_pos,
      last_resource,
      label_index = {};

  buff = BufferCursor(buff);

  if (typeof(packet.edns_version) !== 'undefined') {
    state = WRITE_EDNS;
  } else {
    state = WRITE_HEADER;
  }

  while (true) {
    try {
      switch (state) {
        case WRITE_EDNS:
          val = {
            name: '',
            type: consts.NAME_TO_QTYPE.OPT,
            class: packet.payload
          };
          pos = packet.header.rcode;
          val.ttl = packet.header.rcode >> 4;
          packet.header.rcode = pos - (val.ttl << 4);
          val.ttl = (val.ttl << 8) + packet.edns_version;
          val.ttl = (val.ttl << 16) + (packet.do << 15) & 0x8000;
          packet.additional.splice(0, 0, val);
          state = WRITE_HEADER;
          break;
        case WRITE_HEADER:
          assert(packet.header, 'Packet requires "header"');
          buff.writeUInt16BE(packet.header.id & 0xFFFF);
          val = 0;
          val += (packet.header.qr << 15) & 0x8000;
          val += (packet.header.opcode << 11) & 0x7800;
          val += (packet.header.aa << 10) & 0x400;
          val += (packet.header.tc << 9) & 0x200;
          val += (packet.header.rd << 8) & 0x100;
          val += (packet.header.ra << 7) & 0x80;
          val += (packet.header.res1 << 6) & 0x40;
          val += (packet.header.res1 << 5) & 0x20;
          val += (packet.header.res1 << 4) & 0x10;
          val += packet.header.rcode & 0xF;
          buff.writeUInt16BE(val & 0xFFFF);
          // TODO assert on question.length > 1, in practice multiple questions
          // aren't used
          buff.writeUInt16BE(1);
          // answer offset 6
          buff.writeUInt16BE(packet.answer.length & 0xFFFF);
          // authority offset 8
          buff.writeUInt16BE(packet.authority.length & 0xFFFF);
          // additional offset 10
          buff.writeUInt16BE(packet.additional.length & 0xFFFF);
          state = WRITE_QUESTION;
          break;
        case WRITE_TRUNCATE:
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
          buff.writeUInt16BE(count - 1);
          buff.seek(last_resource);
          state = WRITE_END;
          break;
        case WRITE_NAME_PACK:
          name_pack(name, buff, label_index);
          state = next;
          break;
        case WRITE_QUESTION:
          val = packet.question[0];
          assert(val, 'Packet requires a question');
          assertUndefined(val.name, 'Question requires a "name"');
          name = val.name;
          state = WRITE_NAME_PACK;
          next = WRITE_QUESTION_NEXT;
          break;
        case WRITE_QUESTION_NEXT:
          assertUndefined(val.type, 'Question requires a "type"');
          assertUndefined(val.class, 'Questionn requires a "class"');
          buff.writeUInt16BE(val.type & 0xFFFF);
          buff.writeUInt16BE(val.class & 0xFFFF);
          state = WRITE_RESOURCE_RECORD;
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
          val = packet[section][count];
          assertUndefined(val.name, 'Resource record requires "name"');
          name = val.name;
          state = WRITE_NAME_PACK;
          next = WRITE_RESOURCE_WRITE_NEXT;
          break;
        case WRITE_RESOURCE_WRITE_NEXT:
          assertUndefined(val.type, 'Resource record requires "type"');
          assertUndefined(val.class, 'Resource record requires "class"');
          assertUndefined(val.ttl, 'Resource record requires "ttl"');
          buff.writeUInt16BE(val.type & 0xFFFF);
          buff.writeUInt16BE(val.class & 0xFFFF);
          buff.writeUInt32BE(val.ttl & 0xFFFFFFFF);

          // where the rdata length goes
          rdata_pos = buff.tell();
          buff.writeUInt16BE(0);

          state = val.type;
          break;
        case WRITE_RESOURCE_DONE:
          pos = buff.tell();
          buff.seek(rdata_pos);
          buff.writeUInt16BE(pos - rdata_pos - 2);
          buff.seek(pos);
          count += 1;
          state = WRITE_RESOURCE_RECORD;
          break;
        case WRITE_A:
        case WRITE_AAAA:
          //TODO XXX FIXME -- assert that address is of proper type
          assertUndefined(val.address, 'A/AAAA record requires "address"');
          val = ipaddr.parse(val.address).toByteArray();
          val.forEach(function(b) {
            buff.writeUInt8(b);
          });
          state = WRITE_RESOURCE_DONE;
          break;
        case WRITE_NS:
        case WRITE_CNAME:
        case WRITE_PTR:
          assertUndefined(val.data, 'NS/CNAME/PTR record requires "data"');
          name = val.data;
          state = WRITE_NAME_PACK;
          next = WRITE_RESOURCE_DONE;
          break;
        case WRITE_SPF:
        case WRITE_TXT:
          //TODO XXX FIXME -- split on max char string and loop
          assertUndefined(val.data, 'TXT record requires "data"');
          buff.writeUInt8(val.data.length);
          buff.write(val.data, val.data.length, 'ascii');
          state = WRITE_RESOURCE_DONE;
          break;
        case WRITE_MX:
          assertUndefined(val.priority, 'MX record requires "priority"');
          assertUndefined(val.exchange, 'MX record requires "exchange"');
          buff.writeUInt16BE(val.priority & 0xFFFF);
          name = val.exchange;
          state = WRITE_NAME_PACK;
          next = WRITE_RESOURCE_DONE;
          break;
        case WRITE_SRV:
          assertUndefined(val.priority, 'SRV record requires "priority"');
          assertUndefined(val.weight, 'SRV record requires "weight"');
          assertUndefined(val.port, 'SRV record requires "port"');
          assertUndefined(val.target, 'SRV record requires "target"');
          buff.writeUInt16BE(val.priority & 0xFFFF);
          buff.writeUInt16BE(val.weight & 0xFFFF);
          buff.writeUInt16BE(val.port & 0xFFFF);
          name = val.target;
          state = WRITE_NAME_PACK;
          next = WRITE_RESOURCE_DONE;
          break;
        case WRITE_SOA:
          assertUndefined(val.primary, 'SOA record requires "primary"');
          name = val.primary;
          state = WRITE_NAME_PACK;
          next = WRITE_SOA_ADMIN;
          break;
        case WRITE_SOA_ADMIN:
          assertUndefined(val.admin, 'SOA record requires "admin"');
          name = val.admin;
          state = WRITE_NAME_PACK;
          next = WRITE_SOA_NEXT;
          break;
        case WRITE_SOA_NEXT:
          assertUndefined(val.serial, 'SOA record requires "serial"');
          assertUndefined(val.refresh, 'SOA record requires "refresh"');
          assertUndefined(val.retry, 'SOA record requires "retry"');
          assertUndefined(val.expiration, 'SOA record requires "expiration"');
          assertUndefined(val.minimum, 'SOA record requires "minimum"');
          buff.writeUInt32BE(val.serial & 0xFFFFFFFF);
          buff.writeInt32BE(val.refresh & 0xFFFFFFFF);
          buff.writeInt32BE(val.retry & 0xFFFFFFFF);
          buff.writeInt32BE(val.expiration & 0xFFFFFFFF);
          buff.writeInt32BE(val.minimum & 0xFFFFFFFF);
          state = WRITE_RESOURCE_DONE;
          break;
        case WRITE_OPT:
          while (packet.edns_options.length) {
            val = packet.edns_options.pop();
            buff.writeUInt16BE(val.code);
            buff.writeUInt16BE(val.data.length);
            for (pos = 0; pos < val.data.length; pos++) {
              buff.writeUInt8(val.data.readUInt8(pos));
            }
          }
          state = WRITE_RESOURCE_DONE;
          break;
        case WRITE_NAPTR:
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
          buff.writeUInt8(val.replacement.length);
          buff.write(val.replacement, val.replacement.length, 'ascii');
          state = WRITE_RESOURCE_DONE;
          break;
        case WRITE_END:
          return buff.tell();
          break;
        default:
          throw new Error('WTF No State While Writing');
          break;
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

function parseHeader(msg, packet, counts) {
  packet.header.id = msg.readUInt16BE();
  var val = msg.readUInt16BE();
  packet.header.qr = (val & 0x8000) >> 15;
  packet.header.opcode = (val & 0x7800) >> 11;
  packet.header.aa = (val & 0x400) >> 10;
  packet.header.tc = (val & 0x200) >> 9;
  packet.header.rd = (val & 0x100) >> 8;
  packet.header.ra = (val & 0x80) >> 7;
  packet.header.res1 = (val & 0x40) >> 6;
  packet.header.res2 = (val & 0x20) >> 5;
  packet.header.res3 = (val & 0x10) >> 4;
  packet.header.rcode = (val & 0xF);
  packet.question = new Array(msg.readUInt16BE());
  packet.answer = new Array(msg.readUInt16BE());
  packet.authority = new Array(msg.readUInt16BE());
  packet.additional = new Array(msg.readUInt16BE());
  return PARSE_QUESTION;
}

function parseQuestion(msg, packet) {
  var val = {};
  val.name = nameUnpack(msg);
  val.type = msg.readUInt16BE();
  val.class = msg.readUInt16BE();
  packet.question[0] = val;
  assert(packet.question.length === 1);
  // TODO handle qdcount > 0 in practice no one sends this
  return PARSE_RESOURCE_RECORD;
}

function parseRR(msg, val, rdata) {
  val.name = nameUnpack(msg);
  val.type = msg.readUInt16BE();
  val.class = msg.readUInt16BE();
  val.ttl = msg.readUInt32BE();
  rdata.len = msg.readUInt16BE();
  return val.type;
};

function parseA(val, msg) {
  var address = '' +
    msg.readUInt8() +
    '.' + msg.readUInt8() +
    '.' + msg.readUInt8() +
    '.' + msg.readUInt8();
  val.address = address;
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
  val.data = nameUnpack(msg);
  return PARSE_RESOURCE_DONE;
}

function parseTxt(val, msg, rdata) {
  val.data = '';
  var end = msg.tell() + rdata.len;
  while (msg.tell() != end) {
    val.data += msg.toString('ascii', msg.readUInt8());
  }
  return PARSE_RESOURCE_DONE;
}

function parseMx(val, msg, rdata) {
  val.priority = msg.readUInt16BE();
  val.exchange = nameUnpack(msg);
  return PARSE_RESOURCE_DONE;
}

function parseSrv(val, msg) {
  val.priority = msg.readUInt16BE();
  val.weight = msg.readUInt16BE();
  val.port = msg.readUInt16BE();
  val.target = nameUnpack(msg);
  return PARSE_RESOURCE_DONE;
}

function parseSoa(val, msg) {
  val.primary = nameUnpack(msg);
  val.admin = nameUnpack(msg);
  val.serial = msg.readUInt32BE();
  val.refresh = msg.readInt32BE();
  val.retry = msg.readInt32BE();
  val.expiration = msg.readInt32BE();
  val.minimum = msg.readInt32BE();
  return PARSE_RESOURCE_DONE;
}

function parseNaptr(val, rdata) {
  val.order = msg.readUInt16BE();
  val.preference = msg.readUInt16BE();
  var pos = msg.readUInt8();
  val.flags = msg.toString('ascii', pos);
  pos = msg.readUInt8();
  val.service = msg.toString('ascii', pos);
  pos = msg.readUInt8();
  val.regexp = msg.toString('ascii', pos);
  pos = msg.readUInt8();
  val.replacement = msg.toString('ascii', pos);
  return PARSE_RESOURCE_DONE;
}

var
  PARSE_HEADER          = 100000,
  PARSE_QUESTION        = 100001,
  PARSE_RESOURCE_RECORD = 100002,
  PARSE_RR_UNPACK       = 100003,
  PARSE_RESOURCE_DONE   = 100004,
  PARSE_END             = 100005,
  PARSE_A     = consts.NAME_TO_QTYPE.A,
  PARSE_NS    = consts.NAME_TO_QTYPE.NS,
  PARSE_CNAME = consts.NAME_TO_QTYPE.CNAME,
  PARSE_SOA   = consts.NAME_TO_QTYPE.SOA,
  PARSE_PTR   = consts.NAME_TO_QTYPE.PTR,
  PARSE_MX    = consts.NAME_TO_QTYPE.MX,
  PARSE_TXT   = consts.NAME_TO_QTYPE.TXT,
  PARSE_AAAA  = consts.NAME_TO_QTYPE.AAAA,
  PARSE_SRV   = consts.NAME_TO_QTYPE.SRV,
  PARSE_NAPTR = consts.NAME_TO_QTYPE.NAPTR,
  PARSE_OPT   = consts.NAME_TO_QTYPE.OPT,
  PARSE_SPF   = consts.NAME_TO_QTYPE.SPF;
  

Packet.parse = function(msg) {
  var state,
      pos,
      val,
      rdata,
      counts = {},
      section,
      count;

  var packet = new Packet();

  pos = 0;
  state = PARSE_HEADER;

  msg = BufferCursor(msg);

  while (true) {
    switch (state) {
      case PARSE_HEADER:
        state = parseHeader(msg, packet, counts);
        break;
      case PARSE_QUESTION:
        state = parseQuestion(msg, packet);
        section = 'answer';
        count = 0;
        break;
      case PARSE_RESOURCE_RECORD:
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
        packet[section][count] = val;
        count++;
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
        // assert first entry in additional
        rdata.buf = msg.slice(rdata.len);
        counts[count] -= 1;
        packet.payload = val.class;
        pos = msg.tell();
        msg.seek(pos - 6);
        packet.header.rcode = (msg.readUInt8() << 4) + packet.header.rcode;
        packet.edns_version = msg.readUInt8();
        val = msg.readUInt16BE();
        msg.seek(pos);
        packet.do = (val & 0x8000) << 15;
        while (!rdata.buf.eof()) {
          packet.edns_options.push({
            code: rdata.buf.readUInt16BE(),
            data: rdata.buf.slice(rdata.buf.readUInt16BE()).buffer
          });
        }
        state = PARSE_RESOURCE_RECORD;
        break;
      case PARSE_NAPTR:
        state = parseNaptr(val, msg);
        break;
      case PARSE_END:
        return packet;
        break;
      default:
        //console.log(state, val);
        val.data = msg.slice(rdata.len);
        state = PARSE_RESOURCE_DONE;
        break;
    }
  }
};
