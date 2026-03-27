var fs = require('fs');
var path = require('path');
var vm = require('vm');

var Packet = require('../packet');

var test = require('tap').test;

var fixtureDir = path.join(__dirname, 'fixtures');

var files = fs.readdirSync(fixtureDir).filter(function (f) { return /\.js$/.test(f); });

files.forEach(function (file) {
  test('can write ' + file, function (t) {
    var js = 'foo = ' + fs.readFileSync(path.join(fixtureDir, file), 'utf8');
    js = vm.runInThisContext(js, file);
    var buff = new Buffer(4096);
    var written = Packet.write(buff, js);
    var binFile = path.join(fixtureDir, file.replace(/\.js$/, '.bin'));
    var bin = fs.readFileSync(binFile);
    var rtrip = Packet.parse(buff.slice(0, written));
    t.same(written, bin.length, 'output is of equal size to fixture');
    t.same(buff.slice(0, written), bin, 'output is equal to fixture');
    t.same(rtrip, js, 'reparsed output is equal to fixture');
    t.end();
  });
});
