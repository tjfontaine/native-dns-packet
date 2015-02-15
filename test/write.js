var fs = require('fs');
var path = require('path');
var vm = require('vm');

var Packet = require('../packet');

var test = require('tap').test;

var fixtureDir = path.join(__dirname, 'fixtures');

var files = fs.readdirSync(fixtureDir).filter(function (f) { return /\.js$/.test(f); });

files.forEach(function (file) {
  test('can parse ' + file, function (t) {
    var js = 'foo = ' + fs.readFileSync(path.join(fixtureDir, file), 'utf8');
    js = vm.runInThisContext(js, file);
    var buff = new Buffer(4096);
    var written = Packet.write(buff, js);
    var binFile = path.join(fixtureDir, file.replace(/\.js$/, '.bin'));
    var bin = fs.readFileSync(binFile);
    var rtrip = Packet.parse(buff.slice(0, written));
    t.equivalent(written, bin.length, null, {testMsgLen: file});
    t.equivalent(buff.slice(0, written), bin, null, {testBin: file});
    t.equivalent(rtrip, js, null, {testObj: file});
    t.end();
  });
});


test('truncate additional overflow', function(t){

  var buff, pre, post, len;

  pre = JSON.parse('{"header":{"id":12345,"qr":0,"opcode":0,"aa":0,"tc":0,"rd":1,"ra":0,"res1":0,"res2":0,"res3":0,"rcode":1},"question":[{"name":"really.long.name.some.domain.com","type":1,"class":1}],"answer":[{"type":1,"class":1,"name":"0.0.0.really.long.name.some.domain1.com","address":"127.0.0.0","ttl":600},{"type":1,"class":1,"name":"1.1.1.really.long.name.some.domain1.com","address":"127.0.0.1","ttl":600},{"type":1,"class":1,"name":"2.2.2.really.long.name.some.domain1.com","address":"127.0.0.2","ttl":600},{"type":1,"class":1,"name":"3.3.3.really.long.name.some.domain1.com","address":"127.0.0.3","ttl":600},{"type":1,"class":1,"name":"4.4.4.really.long.name.some.domain1.com","address":"127.0.0.4","ttl":600},{"type":1,"class":1,"name":"5.5.5.really.long.name.some.domain1.com","address":"127.0.0.5","ttl":600}],"authority":[{"type":1,"class":1,"name":"0.0.0.really.long.name.some.domain2.com","address":"127.0.0.0","ttl":600},{"type":1,"class":1,"name":"1.1.1.really.long.name.some.domain2.com","address":"127.0.0.1","ttl":600},{"type":1,"class":1,"name":"2.2.2.really.long.name.some.domain2.com","address":"127.0.0.2","ttl":600},{"type":1,"class":1,"name":"3.3.3.really.long.name.some.domain2.com","address":"127.0.0.3","ttl":600},{"type":1,"class":1,"name":"4.4.4.really.long.name.some.domain2.com","address":"127.0.0.4","ttl":600},{"type":1,"class":1,"name":"5.5.5.really.long.name.some.domain2.com","address":"127.0.0.5","ttl":600}],"additional":[{"type":1,"class":1,"name":"0.0.0.really.long.name.some.domain3.com","address":"127.0.0.0","ttl":600},{"type":1,"class":1,"name":"1.1.1.really.long.name.some.domain3.com","address":"127.0.0.1","ttl":600},{"type":1,"class":1,"name":"2.2.2.really.long.name.some.domain3.com","address":"127.0.0.2","ttl":600},{"type":1,"class":1,"name":"3.3.3.really.long.name.some.domain3.com","address":"127.0.0.3","ttl":600},{"type":1,"class":1,"name":"4.4.4.really.long.name.some.domain3.com","address":"127.0.0.4","ttl":600},{"type":1,"class":1,"name":"5.5.5.really.long.name.some.domain3.com","address":"127.0.0.5","ttl":600},{"type":1,"class":1,"name":"6.6.6.really.long.name.some.domain3.com","address":"127.0.0.6","ttl":600},{"type":1,"class":1,"name":"7.7.7.really.long.name.some.domain3.com","address":"127.0.0.7","ttl":600},{"type":1,"class":1,"name":"8.8.8.really.long.name.some.domain3.com","address":"127.0.0.8","ttl":600},{"type":1,"class":1,"name":"9.9.9.really.long.name.some.domain3.com","address":"127.0.0.9","ttl":600},{"type":1,"class":1,"name":"10.10.10.really.long.name.some.domain3.com","address":"127.0.0.10","ttl":600},{"type":1,"class":1,"name":"11.11.11.really.long.name.some.domain3.com","address":"127.0.0.11","ttl":600},{"type":1,"class":1,"name":"12.12.12.really.long.name.some.domain3.com","address":"127.0.0.12","ttl":600},{"type":1,"class":1,"name":"13.13.13.really.long.name.some.domain3.com","address":"127.0.0.13","ttl":600},{"type":1,"class":1,"name":"14.14.14.really.long.name.some.domain3.com","address":"127.0.0.14","ttl":600},{"type":1,"class":1,"name":"15.15.15.really.long.name.some.domain3.com","address":"127.0.0.15","ttl":600},{"type":1,"class":1,"name":"16.16.16.really.long.name.some.domain3.com","address":"127.0.0.16","ttl":600},{"type":1,"class":1,"name":"17.17.17.really.long.name.some.domain3.com","address":"127.0.0.17","ttl":600},{"type":1,"class":1,"name":"18.18.18.really.long.name.some.domain3.com","address":"127.0.0.18","ttl":600},{"type":1,"class":1,"name":"19.19.19.really.long.name.some.domain3.com","address":"127.0.0.19","ttl":600},{"type":1,"class":1,"name":"20.20.20.really.long.name.some.domain3.com","address":"127.0.0.20","ttl":600},{"type":1,"class":1,"name":"21.21.21.really.long.name.some.domain3.com","address":"127.0.0.21","ttl":600},{"type":1,"class":1,"name":"22.22.22.really.long.name.some.domain3.com","address":"127.0.0.22","ttl":600},{"type":1,"class":1,"name":"23.23.23.really.long.name.some.domain3.com","address":"127.0.0.23","ttl":600},{"type":1,"class":1,"name":"24.24.24.really.long.name.some.domain3.com","address":"127.0.0.24","ttl":600}],"edns_options":[]}');

  buff = new Buffer(512);
  len = Packet.write(buff, pre);
  post = Packet.parse(buff.slice(0, len));
  t.ok(pre.additional.length != post.additional.length, 'Additional should be less because of truncated packet: ' + pre.additional.length + '-' + post.additional.length);

  t.end();
});



test('truncate authority overflow', function(t){

  var buff, pre, post, len;

  pre = JSON.parse('{"header":{"id":12345,"qr":0,"opcode":0,"aa":0,"tc":0,"rd":1,"ra":0,"res1":0,"res2":0,"res3":0,"rcode":1},"question":[{"name":"really.long.name.some.domain.com","type":1,"class":1}],"answer":[{"type":1,"class":1,"name":"0.0.0.really.long.name.some.domain1.com","address":"127.0.0.0","ttl":600},{"type":1,"class":1,"name":"1.1.1.really.long.name.some.domain1.com","address":"127.0.0.1","ttl":600},{"type":1,"class":1,"name":"2.2.2.really.long.name.some.domain1.com","address":"127.0.0.2","ttl":600},{"type":1,"class":1,"name":"3.3.3.really.long.name.some.domain1.com","address":"127.0.0.3","ttl":600},{"type":1,"class":1,"name":"4.4.4.really.long.name.some.domain1.com","address":"127.0.0.4","ttl":600},{"type":1,"class":1,"name":"5.5.5.really.long.name.some.domain1.com","address":"127.0.0.5","ttl":600}],"authority":[{"type":1,"class":1,"name":"0.0.0.really.long.name.some.domain2.com","address":"127.0.0.0","ttl":600},{"type":1,"class":1,"name":"1.1.1.really.long.name.some.domain2.com","address":"127.0.0.1","ttl":600},{"type":1,"class":1,"name":"2.2.2.really.long.name.some.domain2.com","address":"127.0.0.2","ttl":600},{"type":1,"class":1,"name":"3.3.3.really.long.name.some.domain2.com","address":"127.0.0.3","ttl":600},{"type":1,"class":1,"name":"4.4.4.really.long.name.some.domain2.com","address":"127.0.0.4","ttl":600},{"type":1,"class":1,"name":"5.5.5.really.long.name.some.domain2.com","address":"127.0.0.5","ttl":600},{"type":1,"class":1,"name":"6.6.6.really.long.name.some.domain2.com","address":"127.0.0.6","ttl":600},{"type":1,"class":1,"name":"7.7.7.really.long.name.some.domain2.com","address":"127.0.0.7","ttl":600},{"type":1,"class":1,"name":"8.8.8.really.long.name.some.domain2.com","address":"127.0.0.8","ttl":600},{"type":1,"class":1,"name":"9.9.9.really.long.name.some.domain2.com","address":"127.0.0.9","ttl":600},{"type":1,"class":1,"name":"10.10.10.really.long.name.some.domain2.com","address":"127.0.0.10","ttl":600},{"type":1,"class":1,"name":"11.11.11.really.long.name.some.domain2.com","address":"127.0.0.11","ttl":600},{"type":1,"class":1,"name":"12.12.12.really.long.name.some.domain2.com","address":"127.0.0.12","ttl":600},{"type":1,"class":1,"name":"13.13.13.really.long.name.some.domain2.com","address":"127.0.0.13","ttl":600},{"type":1,"class":1,"name":"14.14.14.really.long.name.some.domain2.com","address":"127.0.0.14","ttl":600},{"type":1,"class":1,"name":"15.15.15.really.long.name.some.domain2.com","address":"127.0.0.15","ttl":600},{"type":1,"class":1,"name":"16.16.16.really.long.name.some.domain2.com","address":"127.0.0.16","ttl":600},{"type":1,"class":1,"name":"17.17.17.really.long.name.some.domain2.com","address":"127.0.0.17","ttl":600},{"type":1,"class":1,"name":"18.18.18.really.long.name.some.domain2.com","address":"127.0.0.18","ttl":600},{"type":1,"class":1,"name":"19.19.19.really.long.name.some.domain2.com","address":"127.0.0.19","ttl":600},{"type":1,"class":1,"name":"20.20.20.really.long.name.some.domain2.com","address":"127.0.0.20","ttl":600},{"type":1,"class":1,"name":"21.21.21.really.long.name.some.domain2.com","address":"127.0.0.21","ttl":600},{"type":1,"class":1,"name":"22.22.22.really.long.name.some.domain2.com","address":"127.0.0.22","ttl":600},{"type":1,"class":1,"name":"23.23.23.really.long.name.some.domain2.com","address":"127.0.0.23","ttl":600},{"type":1,"class":1,"name":"24.24.24.really.long.name.some.domain2.com","address":"127.0.0.24","ttl":600}],"additional":[{"type":1,"class":1,"name":"0.0.0.really.long.name.some.domain3.com","address":"127.0.0.0","ttl":600},{"type":1,"class":1,"name":"1.1.1.really.long.name.some.domain3.com","address":"127.0.0.1","ttl":600},{"type":1,"class":1,"name":"2.2.2.really.long.name.some.domain3.com","address":"127.0.0.2","ttl":600},{"type":1,"class":1,"name":"3.3.3.really.long.name.some.domain3.com","address":"127.0.0.3","ttl":600},{"type":1,"class":1,"name":"4.4.4.really.long.name.some.domain3.com","address":"127.0.0.4","ttl":600},{"type":1,"class":1,"name":"5.5.5.really.long.name.some.domain3.com","address":"127.0.0.5","ttl":600}],"edns_options":[]}');

  buff = new Buffer(512);
  len = Packet.write(buff, pre);
  post = Packet.parse(buff.slice(0, len));
  t.ok(pre.authority.length != post.authority.length, 'Authority should be less because of truncated packet: ' + pre.authority.length + '-' + post.authority.length);

  t.end();
});

test('truncate answer overflow', function(t){

  var buff, pre, post, len;

  pre = JSON.parse('{"header":{"id":12345,"qr":0,"opcode":0,"aa":0,"tc":0,"rd":1,"ra":0,"res1":0,"res2":0,"res3":0,"rcode":1},"question":[{"name":"really.long.name.some.domain.com","type":1,"class":1}],"answer":[{"type":1,"class":1,"name":"0.0.0.really.long.name.some.domain1.com","address":"127.0.0.0","ttl":600},{"type":1,"class":1,"name":"1.1.1.really.long.name.some.domain1.com","address":"127.0.0.1","ttl":600},{"type":1,"class":1,"name":"2.2.2.really.long.name.some.domain1.com","address":"127.0.0.2","ttl":600},{"type":1,"class":1,"name":"3.3.3.really.long.name.some.domain1.com","address":"127.0.0.3","ttl":600},{"type":1,"class":1,"name":"4.4.4.really.long.name.some.domain1.com","address":"127.0.0.4","ttl":600},{"type":1,"class":1,"name":"5.5.5.really.long.name.some.domain1.com","address":"127.0.0.5","ttl":600},{"type":1,"class":1,"name":"6.6.6.really.long.name.some.domain1.com","address":"127.0.0.6","ttl":600},{"type":1,"class":1,"name":"7.7.7.really.long.name.some.domain1.com","address":"127.0.0.7","ttl":600},{"type":1,"class":1,"name":"8.8.8.really.long.name.some.domain1.com","address":"127.0.0.8","ttl":600},{"type":1,"class":1,"name":"9.9.9.really.long.name.some.domain1.com","address":"127.0.0.9","ttl":600},{"type":1,"class":1,"name":"10.10.10.really.long.name.some.domain1.com","address":"127.0.0.10","ttl":600},{"type":1,"class":1,"name":"11.11.11.really.long.name.some.domain1.com","address":"127.0.0.11","ttl":600},{"type":1,"class":1,"name":"12.12.12.really.long.name.some.domain1.com","address":"127.0.0.12","ttl":600},{"type":1,"class":1,"name":"13.13.13.really.long.name.some.domain1.com","address":"127.0.0.13","ttl":600},{"type":1,"class":1,"name":"14.14.14.really.long.name.some.domain1.com","address":"127.0.0.14","ttl":600},{"type":1,"class":1,"name":"15.15.15.really.long.name.some.domain1.com","address":"127.0.0.15","ttl":600},{"type":1,"class":1,"name":"16.16.16.really.long.name.some.domain1.com","address":"127.0.0.16","ttl":600},{"type":1,"class":1,"name":"17.17.17.really.long.name.some.domain1.com","address":"127.0.0.17","ttl":600},{"type":1,"class":1,"name":"18.18.18.really.long.name.some.domain1.com","address":"127.0.0.18","ttl":600},{"type":1,"class":1,"name":"19.19.19.really.long.name.some.domain1.com","address":"127.0.0.19","ttl":600},{"type":1,"class":1,"name":"20.20.20.really.long.name.some.domain1.com","address":"127.0.0.20","ttl":600},{"type":1,"class":1,"name":"21.21.21.really.long.name.some.domain1.com","address":"127.0.0.21","ttl":600},{"type":1,"class":1,"name":"22.22.22.really.long.name.some.domain1.com","address":"127.0.0.22","ttl":600},{"type":1,"class":1,"name":"23.23.23.really.long.name.some.domain1.com","address":"127.0.0.23","ttl":600},{"type":1,"class":1,"name":"24.24.24.really.long.name.some.domain1.com","address":"127.0.0.24","ttl":600}],"authority":[{"type":1,"class":1,"name":"0.0.0.really.long.name.some.domain2.com","address":"127.0.0.0","ttl":600},{"type":1,"class":1,"name":"1.1.1.really.long.name.some.domain2.com","address":"127.0.0.1","ttl":600},{"type":1,"class":1,"name":"2.2.2.really.long.name.some.domain2.com","address":"127.0.0.2","ttl":600},{"type":1,"class":1,"name":"3.3.3.really.long.name.some.domain2.com","address":"127.0.0.3","ttl":600},{"type":1,"class":1,"name":"4.4.4.really.long.name.some.domain2.com","address":"127.0.0.4","ttl":600},{"type":1,"class":1,"name":"5.5.5.really.long.name.some.domain2.com","address":"127.0.0.5","ttl":600}],"additional":[{"type":1,"class":1,"name":"0.0.0.really.long.name.some.domain3.com","address":"127.0.0.0","ttl":600},{"type":1,"class":1,"name":"1.1.1.really.long.name.some.domain3.com","address":"127.0.0.1","ttl":600},{"type":1,"class":1,"name":"2.2.2.really.long.name.some.domain3.com","address":"127.0.0.2","ttl":600},{"type":1,"class":1,"name":"3.3.3.really.long.name.some.domain3.com","address":"127.0.0.3","ttl":600},{"type":1,"class":1,"name":"4.4.4.really.long.name.some.domain3.com","address":"127.0.0.4","ttl":600},{"type":1,"class":1,"name":"5.5.5.really.long.name.some.domain3.com","address":"127.0.0.5","ttl":600}],"edns_options":[]}');

  buff = new Buffer(512);
  len = Packet.write(buff, pre);
  post = Packet.parse(buff.slice(0, len));
  t.ok(pre.answer.length != post.answer.length, 'Answer should be less because of truncated packet: ' + pre.answer.length + '-' + post.answer.length);

  t.end();
});





