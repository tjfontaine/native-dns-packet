Daplie is Taking Back the Internet!
--------------

[![](https://daplie.github.com/igg/images/ad-developer-rpi-white-890x275.jpg?v2)](https://daplie.com/preorder/)

Stop serving the empire and join the rebel alliance!

* [Invest in Daplie on Wefunder](https://daplie.com/invest/)
* [Pre-order Cloud](https://daplie.com/preorder/), The World's First Home Server for Everyone

native-dns-packet
-----------------

 * `Packet.parse(buffer)` returns an instance of `Packet`
 * `Packet.write(buffer, packet)` writes the given packet into the buffer,
truncating where appropriate

```javascript
var Packet = function () {
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
  this.question = [];
  this.answer = [];
  this.authority = [];
  this.additional = [];
  this.edns_options = [];
  this.payload = undefined;
};
```

## History

###### 0.1.1 - October 5, 2014

- Fixing NPM tagging issue...

###### 0.1.0 - October 2, 2014

- Added TLSA support
- Fixed EDNS & NAPTR support + deprecates some EDNS fields on Packet
- Now includes support for forwarding EDNS responses (Packet.edns)
- Added many TODOs with suggested improvements
- Added many links to GH issues and RFCs
- Cleaned up code a bit to better please linters
- Added deprecation notices (see parseOpt)
- Handle unhandled RRs on writing packet instead of throwing exception.
- edns/opt should use BufferCursor.copy (Fixes #11)
- Updated `package.json` to include all authors
- Merged tj's `master` branch to add License info
- Updated README to include history of changes
