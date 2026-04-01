var fs = require('fs');
var path = require('path');
var vm = require('vm');

var Packet = require('../packet');

var test = require('tap').test;

var fixtureDir = path.join(__dirname, 'fixtures');

var files = fs.readdirSync(fixtureDir).filter(function (f) { return /\.bin$/.test(f); });

files.forEach(function (file) {
  test('can parse ' + file, function (t) {
    var bin = fs.readFileSync(path.join(fixtureDir, file));
    var jsFile = path.join(fixtureDir, file.replace(/\.bin$/, '.js'));
    var js = 'foo = ' + fs.readFileSync(jsFile, 'utf8');
    js = vm.runInThisContext(js, jsFile);
    var ret = Packet.parse(bin);

    // Remove Raw Data from RTRIP for comparison
    var i;
    for(i = 0; i < ret.question.length; i++) { delete ret.question[i].nameRaw; }
    for(i = 0; i < ret.answer.length; i++) { delete ret.answer[i].nameRaw; delete ret.answer[i].dataRaw; delete ret.answer[i].targetRaw; delete ret.answer[i].exchangeRaw}
    for(i = 0; i < ret.additional.length; i++) { delete ret.additional[i].nameRaw;}
    for(i = 0; i < ret.authority.length; i++) { delete ret.authority[i].nameRaw;}

    t.equivalent(ret, js);
    t.end();
  });
});
