const jsdom = require("jsdom");
const { JSDOM } = jsdom;

const dom = new JSDOM(`<!DOCTYPE html>
<html>
<head>
    <title>FLARE Meme Maker 3000</title>
    <style>
        h1 {
            font-family: cursive;
            text-align: center;
        }

        #controls {
            text-align: center;
        }

        #remake, #meme-template {
            font-family: cursive;
        }

        #meme-container {
            position: relative;
            width: 400px;
            margin: 20px auto;
        }

        #meme-image {
            width: 100%;
            display: block;
        }

        .caption {
            font-family: "Impact";
            color: white;
            text-shadow: -1px 0 black, 0 1px black, 1px 0 black, 0 -1px black;
            font-size: 24px;
            text-align: center;
            position: absolute;
            /* width: 80%; /* Adjust width as needed */
            padding: 10px;
            background-color: rgba(0, 0, 0, 0);
        }

        #caption1 { top: 10px; left: 50%; transform: translateX(-50%); }
        #caption2 { bottom: 10px; left: 50%; transform: translateX(-50%); }
        #caption2 { bottom: 10px; left: 50%; transform: translateX(-50%); }
    </style>
</head>
<body>
    <h1>FLARE Meme Maker 3000</h1>

    <div id="controls">
        <select id="meme-template">
            <option value="doge1.png">Doge</option>
            <option value="draw.jpg">Draw 25</option>
            <option value="drake.jpg">Drake</option>
            <option value="two_buttons.jpg">Two Buttons</option>
            <option value="boy_friend0.jpg">Distracted Boyfriend</option>
            <option value="success.jpg">Success</option>
            <option value="disaster.jpg">Disaster</option>
            <option value="aliens.jpg">Aliens</option>
        </select>
        <button id="remake">Remake</button>
    </div>

    <div id="meme-container">
        <img id="meme-image" src="" alt="">
        <div id="caption1" class="caption" contenteditable></div>
        <div id="caption2" class="caption" contenteditable></div>
        <div id="caption3" class="caption" contenteditable></div>
    </div>`, {
    url: "https://example.org/",
    referrer: "https://example.com/",
    contentType: "text/html",
    includeNodeLocations: true,
    storageQuota: 10000000
  });

const document = dom.window.document;



function solve() {
    const a =  Object['keys'](a0e)[5]
    const b = a0c[14];
    const c = a0c[a0c['length'] - 1];
    const d = a0c[22];    
    var f = d[3] + 'h' + a[10] + b[2] + a[3] + c[5] + c[c['length'] - 1] + '5' + a[3] + '4' + a[3] + c[2] + c[4] + c[3] + '3' + d[2] + a[3] + 'j4' + a0c[1][2] + d[4] + '5' + c[2] + d[5] + '1' + c[11] + '7' + a0c[21][1] + b['replace'](' ', '-') + a[11] + a0c[4]['substring'](12, 15);
    
    console.log(f['toLowerCase']())
}

solve();