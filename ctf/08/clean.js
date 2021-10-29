const esprima = require('esprima')
const fs = require('fs');
const _ = require('lodash');

function isFunc(node) {
    const name = _.get(node,'id.name')
    const whiteList = ['Add','S8PnPCDSnKdSqe'] // don't remove those
    if (_.includes(whiteList,name)) {
        return false
    }
    if (node.type == 'FunctionDeclaration') {
        return true;
    }
    return false;
}

function removeCalls(source) {
    const entries = [];
    esprima.parseScript(source, {}, function (node, meta) {
        if (isFunc(node)) {
            entries.push({
                start: meta.start.offset,
                end: meta.end.offset
            });
        }
    });
    entries.sort((a, b) => { return b.end - a.end }).forEach(n => {
        let replacement = Array(n.end-n.start).fill('\n') // fill functions with new lines
        source = source.slice(0, n.start) + replacement + source.slice(n.end);
    });
    return source.replace(/\n,/g,'')
}
    let input = fs.readFileSync('./input.js','utf-8')
    let result = removeCalls(input);
    fs.writeFileSync('./cleaned.js',result)