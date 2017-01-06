var fs = require('fs');
var path = require('path');
var vm = require('vm');

var Packet = require('../packet');

var test = require('tap').test;

var fixtureDir = path.join(__dirname, 'fixtures');

var files = fs.readdirSync(fixtureDir).filter(function (f) {
    return /\.js$/.test(f);
});

files.forEach(function (file) {
    test('can parse ' + file, function (t) {
        var js = 'foo = ' + fs.readFileSync(path.join(fixtureDir, file), 'utf8');
        js = vm.runInThisContext(js, file);
        var buff = new Buffer(4096);
        var written = Packet.write(buff, js);
        var binFile = path.join(fixtureDir, file.replace(/\.js$/, '.bin'));
        var bin = fs.readFileSync(binFile);
        var rtrip = Packet.parse(buff.slice(0, written));

        // Remove Raw Data from RTRIP for comparison
        var i;
        for(i = 0; i < rtrip.question.length; i++) { delete rtrip.question[i].nameRaw; }
        for(i = 0; i < rtrip.answer.length; i++) { delete rtrip.answer[i].nameRaw; delete rtrip.answer[i].dataRaw; delete rtrip.answer[i].targetRaw; delete rtrip.answer[i].exchangeRaw}
        for(i = 0; i < rtrip.additional.length; i++) { delete rtrip.additional[i].nameRaw;}
        for(i = 0; i < rtrip.authority.length; i++) { delete rtrip.authority[i].nameRaw;}

        t.equivalent(written, bin.length, {}, {testMsgLen: file});
        t.equivalent(buff.slice(0, written), bin, {}, {testBin: file});
        t.equivalent(rtrip, js, {}, {testObj: file});
        t.end();
    });
});
